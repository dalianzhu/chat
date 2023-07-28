package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"

	"chat/repo"

	"golang.org/x/exp/slices"
)

const OpenAIURL = "api.openai.com"

type ProxyHandler struct {
	OpenAIKey    func(*http.Request) string
	user         *repo.UserRepo
	modelFilters []string
}

// NewProxyHandler creates a new ProxyHandler.
func NewProxyHandler(getKey func(*http.Request) string, user *repo.UserRepo, modelFilters []string) *ProxyHandler {
	return &ProxyHandler{
		OpenAIKey:    getKey,
		user:         user,
		modelFilters: modelFilters,
	}
}

// Proxy is the handler for the openai proxy.
func (p *ProxyHandler) Proxy(w http.ResponseWriter, r *http.Request) {
	// CORS
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.WriteHeader(http.StatusOK)
		return
	}

	auth := r.Header.Get("Authorization")

	log.Println("auth: ", auth)
	if auth == "" {
		w.WriteHeader(401)
		w.Write([]byte("Unauthorized"))
		return
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	if !p.checkToken(token) {
		w.WriteHeader(401)
		w.Write([]byte("Unauthorized"))
		return
	}

	director := func(req *http.Request) {
		req.URL.Scheme = "https"
		req.URL.Host = OpenAIURL
		req.Host = OpenAIURL
		req.Header.Set("Authorization", "Bearer "+p.OpenAIKey(r))
	}
	proxy := &httputil.ReverseProxy{Director: director}
	// proxy.ServeHTTP(w, r)
	p.hijackHttp(w, r, proxy.ServeHTTP)
	log.Printf("[*] receive the destination website response header: %s\n", w.Header())
}

func (p *ProxyHandler) hijackHttp(w http.ResponseWriter, r *http.Request, fn func(rw http.ResponseWriter, req *http.Request)) {
	// 读取原始请求中的 Body 数据
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body:%v\n", err)
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}
	var bodyMap map[string]interface{}
	err = json.Unmarshal(body, &bodyMap)
	if err != nil {
		log.Printf("unmarshal error:%v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	modelName, ok := bodyMap["model"].(string)
	if ok {
		if len(p.modelFilters) != 0 && !slices.Contains(p.modelFilters, modelName) {
			log.Printf("model name not in allowed list:%v\n", p.modelFilters)
			http.Error(w, fmt.Sprintf("model name not in allowed list:%v", p.modelFilters),
				http.StatusForbidden)
			return
		}
	}

	newReq, err := http.NewRequest(r.Method, r.URL.String(), bytes.NewBuffer(body))
	if err != nil {
		http.Error(w, "Error creating new request", http.StatusInternalServerError)
		return
	}
	newReq = newReq.WithContext(r.Context())
	for key, body := range r.Header {
		newReq.Header.Add(key, body[0])
	}
	fn(w, newReq)
}

func (p *ProxyHandler) checkToken(token string) bool {
	user := p.user.GetByToken(token)
	if user == nil || user.Token != token {
		return false
	}
	log.Println("user name: ", user.Username)
	p.user.UpdateCount(user)
	return true
}
