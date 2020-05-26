package oauth

import (
	"encoding/json"
	"fmt"
	"github.com/lelinu/api_utils/utils/error_utils"
	"github.com/mercadolibre/golang-restclient/rest"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	headerXPublic   = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-Caller-Id"

	paramAccessToken = "access_token_id"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL:"http://localhost:8080",
		Timeout:200*time.Millisecond,
	}
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64 `json:"user_id"`
	ClientId int64 `json:"client_id"`
}

func IsPublic(req *http.Request) bool {
	if req == nil {
		return true
	}
	return req.Header.Get(headerXPublic) == "true"
}

func GetCallerId(req *http.Request) int64{
	if req == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(req.Header.Get(headerXCallerId), 10, 64)
	if err != nil{
		return 0
	}
	return callerId
}

func GetClientId(req *http.Request) int64{
	if req == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(req.Header.Get(headerXClientId), 10, 64)
	if err != nil{
		return 0
	}
	return clientId
}

func AuthenticateRequest(req *http.Request) *error_utils.ApiError {
	if req == nil {
		return nil
	}

	cleanRequest(req)

	accessTokenId := strings.TrimSpace(req.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenId)
	if err != nil{
		if err.HttpStatusCode == http.StatusNotFound{
			return nil
		}
		return err
	}

	req.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))
	req.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))

	return nil
}

func cleanRequest(req *http.Request){
	if req == nil{
		return
	}
	req.Header.Del(headerXClientId)
	req.Header.Del(headerXCallerId)
}

func getAccessToken(accessTokenId string) (*accessToken, *error_utils.ApiError){
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))

	// timeout
	if response == nil || response.Response == nil {
		return nil, error_utils.NewInternalServerError("invalid rest client response when trying to get access token")
	}
	// error situation
	if response.StatusCode > 299 {
		var apiError error_utils.ApiError
		if err := json.Unmarshal(response.Bytes(), &apiError); err != nil {
			return nil, error_utils.NewInternalServerError("invalid rest error interface when trying to get access token")
		}
		return nil, &apiError
	}

	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, error_utils.NewInternalServerError("invalid rest user interface")
	}

	return &at, nil
}
