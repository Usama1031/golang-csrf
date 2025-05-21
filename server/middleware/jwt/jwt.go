package jwt

import (
	"crypto/rsa"
	"errors"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/usama1031/golang-csrf/db"
	"github.com/usama1031/golang-csrf/db/models"
)

const (
	privKeyPath = "keys/app.rsa"
	pubKeyPath  = "keys/app.rsa.pub"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

func InitJWT() error {
	signBytes, err := os.ReadFile(privKeyPath)
	if err != nil {
		return err
	}

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)

	if err != nil {
		return err
	}

	verifyBytes, err := os.ReadFile(pubKeyPath)

	if err != nil {
		return err
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)

	if err != nil {
		return err
	}
	return nil
}

func CreateNewTokens(uuid, role string) (authTokenString, refreshTokenString, csrfSecret string, err error) {
	// generate CSRF secrets, refresh token, and auth token

	csrfSecret, err = models.GenerateCSRFSecret()
	if err != nil {
		return
	}
	refreshTokenString, err = createRefreshTokenString(uuid, role, csrfSecret)
	authTokenString, err = createAuthTokenString(uuid, role, csrfSecret)

	if err != nil {
		return
	}
	return
}

func CheckAndRefreshTokens(oldAuthTokenString, oldRefreshTokenString, oldCsrfSecret string) (newAuthTokenString, newRefreshTokenString, newCsrfSecret string, err error) {

	if oldCsrfSecret == "" {
		log.Println("No CSRF token!")
		err = errors.New("Unauthorized")
		return
	}

	authToken, err := jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
	if !ok {
		return
	}

	if oldCsrfSecret != authTokenClaims.Csrf {
		log.Println("CSRF token doesn't match jwt!")
		err = errors.New("Unauthorized")
	}

	if authToken.Valid {
		log.Println("Auth token is valid")

		newCsrfSecret = authTokenClaims.Csrf

		newRefreshTokenString, err = updateRefreshTokenExpiry(oldRefreshTokenString)

		newAuthTokenString = oldAuthTokenString
		return
	} else if errors.Is(err, jwt.ErrTokenExpired) {
		log.Println("Auth token is expired")

		newAuthTokenString, newCsrfSecret, err = updateAuthTokenString(oldRefreshTokenString, oldAuthTokenString)

		if err != nil {
			return
		}

		newRefreshTokenString, err = updateRefreshTokenExpiry(oldRefreshTokenString)

		if err != nil {
			return
		}

		newRefreshTokenString, err = updateRefreshTokenCsrf(newRefreshTokenString, newCsrfSecret)

		return
	} else {
		log.Println("error in auth token")
		err = errors.New("error in auth token")
		return
	}

	err = errors.New("Unauthorized")
	return

}

func createAuthTokenString(uuid, role, csrfSecret string) (authTokenString string, err error) {

	authTokenExp := jwt.NewNumericDate(time.Now().Add(models.AuthTokenValidTime))
	authClaims := models.TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   uuid,
			ExpiresAt: authTokenExp,
		},
		Role: role,
		Csrf: csrfSecret,
	}
	authJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), authClaims)
	authTokenString, err = authJwt.SignedString(signKey)
	return

}

func createRefreshTokenString(uuid, role, csrfSecret string) (refreshTokenString string, err error) {

	refreshJti, err := db.StoreRefreshToken()
	if err != nil {
		return
	}

	refreshClaims := models.TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        refreshJti,
			Subject:   uuid,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(models.RefreshTokenValidTime)),
		},
		Role: role,
		Csrf: csrfSecret,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)
	refreshTokenString, err = refreshJwt.SignedString(signKey)
	return

}

func updateRefreshTokenExpiry(oldRefreshTokenString string) (newRefreshTokenString string, err error) {

	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	oldRefreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return
	}

	refreshClaims := models.TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        oldRefreshTokenClaims.RegisteredClaims.ID,
			Subject:   oldRefreshTokenClaims.RegisteredClaims.Subject,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(models.RefreshTokenValidTime)),
		},
		Role: oldRefreshTokenClaims.Role,
		Csrf: oldRefreshTokenClaims.Csrf,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)

	newRefreshTokenString, err = refreshJwt.SignedString(signKey)

	return
}

func updateAuthTokenString(refreshTokenString, oldAuthTokenString string) (newAuthTokenString, csrfSecret string, err error) {

	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	refreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		err = errors.New("error reading jwt claims")
		return
	}

	if db.CheckRefreshToken(refreshTokenClaims.RegisteredClaims.ID) {
		if refreshToken.Valid {
			authToken, _ := jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
				return verifyKey, nil
			})

			oldAuthTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
			if !ok {
				err = errors.New("error reading jwt claims")
				return
			}
			csrfSecret, err = models.GenerateCSRFSecret()

			if err != nil {
				return
			}

			createAuthTokenString(oldAuthTokenClaims.RegisteredClaims.Subject, oldAuthTokenClaims.Role, csrfSecret)
			return

		} else {
			log.Println("refresh token has expired")
			db.DeleteRefreshToken(refreshTokenClaims.RegisteredClaims.ID)

			err = errors.New("Unauthorized")
			return
		}
	} else {
		log.Println("refresh token has been revoked")
		err = errors.New("Unauthorized")
		return
	}
}

func RevokeRefreshToken(refreshTokenString string) error {
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		return errors.New("could not parse refresh token with claims")
	}

	refreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return errors.New("could not read refresh token claims")
	}

	db.DeleteRefreshToken(refreshTokenClaims.RegisteredClaims.ID)
	return nil
}

func updateRefreshTokenCsrf(oldRefreshTokenString, newCsrfString string) (newRefreshTokenString string, err error) {

	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	oldRefreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return
	}

	refreshClaims := models.TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        oldRefreshTokenClaims.RegisteredClaims.ID,
			Subject:   oldRefreshTokenClaims.RegisteredClaims.Subject,
			ExpiresAt: oldRefreshTokenClaims.RegisteredClaims.ExpiresAt,
		},
		Role: oldRefreshTokenClaims.Role,
		Csrf: newCsrfString,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)

	newRefreshTokenString, err = refreshJwt.SignedString(signKey)
	return

}

func GrabUUID(authTokenString string) (string, error) {
	authToken, _ := jwt.ParseWithClaims(authTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return "", errors.New("Error fetching claims")
	})

	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)

	if !ok {
		return "", errors.New("errors fetching claims")
	}

	return authTokenClaims.RegisteredClaims.Subject, nil
}
