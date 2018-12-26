package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	debug bool
)

func doLogin(client *http.Client, ip, username, password string) (string, error) {
	response, err := client.PostForm("http://"+ip+"/cgi/login.cgi", url.Values{"name": {username}, "pwd": {password}})
	if debug {
		log.Println(response, err)
	}
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if debug {
		log.Println(response.Body)
	} else {
		io.Copy(ioutil.Discard, response.Body)
	}
	for _, c := range response.Cookies() {
		if c.Name == "SID" && len(c.Value) > 0 {
			return c.Value, nil
		}
	}
	return "", errors.New("SID cookie not found")
}

func getCertStatus(client *http.Client, ip, sid string) (string, error) {
	statusRequest, err := http.NewRequest("POST", "http://"+ip+"/cgi/ipmi.cgi",
		strings.NewReader(url.Values{"SSL_STATUS.XML": {"(0,0)"}, "time_stamp": {time.Now().String()}}.Encode()))
	if err != nil {
		return "", err
	}
	statusRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	statusRequest.AddCookie(&http.Cookie{Name: "SID", Value: sid})
	statusResponse, err := client.Do(statusRequest)
	if debug {
		log.Println(statusResponse, err)
	}
	if err != nil {
		return "", err
	}
	defer statusResponse.Body.Close()
	status, err := ioutil.ReadAll(statusResponse.Body)
	if err != nil {
		return "", err
	}
	return string(status), nil
}

func addMultipartFile(w *multipart.Writer, fieldname, filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	fw, err := w.CreateFormFile(fieldname, filepath.Base(file.Name())+".pem")
	if err != nil {
		return err
	}
	if _, err = io.Copy(fw, file); err != nil {
		return err
	}
	return nil
}

func uploadCert(client *http.Client, ip, sid, certFile, keyFile string) error {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	err := addMultipartFile(w, "/tmp/cert.pem", certFile)
	if err != nil {
		return err
	}
	err = addMultipartFile(w, "/tmp/key.pem", keyFile)
	if err != nil {
		return err
	}
	w.Close()
	uploadRequest, err := http.NewRequest("POST", "http://"+ip+"/cgi/upload_ssl.cgi", &b)
	if err != nil {
		return err
	}
	uploadRequest.Header.Set("Content-Type", w.FormDataContentType())
	uploadRequest.Header.Set("Referer", "http://"+ip+"/cgi/url_redirect.cgi?url_name=config_ssl")
	//	uploadRequest.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0")
	//	uploadRequest.Header.Set("Upgrade-Insecure-Requests", "1")
	//	uploadRequest.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	//	uploadRequest.Header.Set("Accept-Language", "en-US,hu-HU;q=0.8,hu;q=0.5,en;q=0.3")
	uploadRequest.AddCookie(&http.Cookie{Name: "SID", Value: sid})
	//	uploadRequest.AddCookie(&http.Cookie{Name: "langSetFlag", Value: "0"})
	//	uploadRequest.AddCookie(&http.Cookie{Name: "language", Value: "English"})
	//	uploadRequest.AddCookie(&http.Cookie{Name: "subpage", Value: "config_ssl"})
	//	uploadRequest.AddCookie(&http.Cookie{Name: "mainpage", Value: "configuration"})
	uploadResponse, err := client.Do(uploadRequest)
	if debug {
		log.Println(uploadResponse, err)
	}
	if err != nil {
		return err
	}
	defer uploadResponse.Body.Close()
	upload, err := ioutil.ReadAll(uploadResponse.Body)
	if err != nil {
		return err
	}
	if debug {
		log.Println(string(upload))
	}
	if !strings.Contains(string(upload), "LANG_CONFIG_SSL_UPLOAD") {
		return errors.New("no valid response")
	}
	return nil
}

func validateCert(client *http.Client, ip, sid string) (string, error) {
	validateRequest, err := http.NewRequest("POST", "http://"+ip+"/cgi/ipmi.cgi",
		strings.NewReader(url.Values{"SSL_VALIDATE.XML": {"(0,0)"}, "time_stamp": {time.Now().String()}}.Encode()))
	if err != nil {
		return "", nil
	}
	validateRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	validateRequest.AddCookie(&http.Cookie{Name: "SID", Value: sid})
	validateResponse, err := client.Do(validateRequest)
	if debug {
		log.Println(validateResponse, err)
	}
	if err != nil {
		return "", nil
	}
	defer validateResponse.Body.Close()
	validate, err := ioutil.ReadAll(validateResponse.Body)
	if err != nil {
		return "", nil
	}
	return string(validate), nil
}

func getCwd() string {
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalln(err)
	}
	return cwd
}

func main() {
	usernamePtr := flag.String("username", "", "login username")
	passwordPtr := flag.String("password", "", "login password")
	certFilePtr := flag.String("cert", "", "cert file")
	keyFilePtr := flag.String("key", "", "key file")
	basePathPtr := flag.String("base", getCwd(), "certificates base path")
	flag.BoolVar(&debug, "debug", false, "enable debug")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s: [options] ipmi_ip\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	log.SetOutput(os.Stderr)

	if flag.NArg() != 1 || len(flag.Arg(0)) == 0 || len(*usernamePtr) == 0 || len(*passwordPtr) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	ip := flag.Arg(0)
	client := http.DefaultClient
	if len(*certFilePtr) == 0 {
		*certFilePtr = filepath.Join(*basePathPtr, "ipmi_"+ip+".crt");
	}
	if len(*keyFilePtr) == 0 {
		*keyFilePtr = filepath.Join(*basePathPtr, "ipmi_"+ip+".key");
	}

	sid, err := doLogin(client, ip, *usernamePtr, *passwordPtr)
	if err != nil {
		log.Fatalln("Login failed: " + err.Error())
	}

	status, err := getCertStatus(client, ip, sid)
	if err != nil {
		log.Fatalln("Cert status failed: " + err.Error())
	}
	fmt.Println("Before status: " + status)

	err = uploadCert(client, ip, sid, *certFilePtr, *keyFilePtr)
	if err != nil {
		log.Fatalln("Validating cert failed: " + err.Error())
	}
	validate, err := validateCert(client, ip, sid)
	fmt.Println("Validate: " + validate)

	status, err = getCertStatus(client, ip, sid)
	if err != nil {
		log.Fatalln("Cert status failed: " + err.Error())
	}
	fmt.Println("After status: " + status)
}
