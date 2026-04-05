package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"fmt"
)

import(
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"time"
)

import(
	"encoding/json"
)


import (
	"crypto/rand"
	"encoding/hex"
)

func code() string {
	b := make([]byte, 16)       // 16 bytes = 32 hex digits
	_, _ = rand.Read(b)          // ignore error for brevity
	return hex.EncodeToString(b)
}



var db *sql.DB

type User struct {
	UserID     int     `json:"user_id"`
	UserName   string  `json:"user_name"`
	UserNick   string  `json:"user_nick"`
	UserImage  string  `json:"user_image"`
}

type Response struct {
	Status       string  `json:"status"`
	AccessToken  string  `json:"access_token"`
	IDToken      string  `json:"id_token"`
	ExpiresOn    string  `json:"expires_on"`
	TokenType    string  `json:"token_type"`
	User         *User   `json:"user"`
}

// ---------- MAIN ----------
func main() {
	
	row("PASS SERVER")

	PORT := argument("port")
	ROOT := argument("root")
	BASE := argument("base")

	if PORT == "" {
		log.Fatal("port parameters needed: path=8080")
		return
	}
	
	if( !strings.HasPrefix(BASE,"/") ){
		BASE = "/" + BASE
	}


  db, _ = sql.Open(
    "mysql", 
    "master:master@unix(/run/mysqld/mysqld.sock)/db?parseTime=true",
  )

  db.SetMaxOpenConns(50)
  db.SetMaxIdleConns(50)
  db.SetConnMaxLifetime(5 * time.Minute)

	
	write("├─── PORT: ", PORT);
	write("├─── ROOT: ", ROOT);
	write("├─── BASE: ", BASE);


	ROOT = filepath.Clean(ROOT)


	Authorize_File, _ := os.ReadFile("./pages/authorize.html")
	Authorize := string(Authorize_File)


	http.HandleFunc("/!pass/request", func(w http.ResponseWriter, r *http.Request) {

		//response_type  := r.URL.Query().Get("response_type")
		//scope          := r.URL.Query().Get("scope")
		client_id      := r.URL.Query().Get("client_id")
		redirect_uri   := r.URL.Query().Get("redirect_uri")
		state          := r.URL.Query().Get("state")
		
		
		var app_name,app_image,app_verify,app_link string
		err := db.QueryRow("SELECT name,icon,verify,link FROM `app` WHERE id = ? LIMIT 1", ToNumber(client_id)).Scan(&app_name,&app_image,&app_verify,&app_link)
		if err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			http.ServeFile(w, r, "./pages/app-not-found.html")
			return
		}

		if(app_verify=="1" && app_link!=redirect_uri){
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			http.ServeFile(w, r, "./pages/response-is-not-verified.html")
			return
		}


		cookie, err := r.Cookie("auth_session")
    if err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			http.ServeFile(w, r, "./pages/not-logined.html")
			return
    }


    token := cookie.Value

		var user_id int
		db.QueryRow("SELECT `user_id` FROM `session` WHERE `token` = ? AND `expire` > UNIX_TIMESTAMP()", token).Scan(&user_id)
		if(user_id<1){
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			http.ServeFile(w, r, "./pages/not-logined.html")
			return
		}

		var user_name,user_nick,user_image string
		db.QueryRow("SELECT `name`,`nick`,`image` FROM `user` WHERE `id` = ?", user_id).Scan(&user_name,&user_nick,&user_image)
		
		auth_code := code()

		_,e := db.Exec("INSERT INTO `auth` (user_id, app_id, auth_code) VALUES (?, ?, ?)", user_id, client_id, auth_code)
		if(e!=nil){
			write(e)
		}


		code := app_name + ";;" + app_image + ";;" + redirect_uri + ";;" + client_id + ";;" + state + ";;" + ToString(user_id) + ";;" + user_name + ";;" + user_nick + ";;" + user_image + ";;" + auth_code 
		fill := "<script>CODE=\""+strings.ReplaceAll(code, `"`, `\"`)+"\"</script>\n"
    


		//Authorize_File, _ = os.ReadFile("./pages/authorize.html")
		//Authorize = string(Authorize_File)


		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintln(w, fill + Authorize)		
	})





	http.HandleFunc("/!pass/token", func(w http.ResponseWriter, r *http.Request) {

    // Parse form data (for both POST and GET)
    err_parse := r.ParseForm()
    if err_parse != nil {
        http.Error(w, "Unable to parse form", http.StatusBadRequest)
        return
    }

    // Access individual form values
    //grantType := r.FormValue("grant_type")
    code := r.FormValue("code")
    redirect_uri := r.FormValue("redirect_uri")
    client_id := r.FormValue("client_id")
    client_secret := r.FormValue("client_secret")

		
		var app_link string
		err := db.QueryRow("SELECT link FROM `app` WHERE id = ? AND link=? AND api_token=? LIMIT 1", ToNumber(client_id),redirect_uri,client_secret).Scan(&app_link)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, "{\"status\": \"error\", \"message\": \"App Not Found\" }")
			return
		}



		_,err = db.Exec("DELETE FROM `auth` WHERE `created_at` < NOW() - INTERVAL 1 MINUTE;")
		if(err!=nil){
			write(err)
		}
		

		var user_id int
		db.QueryRow("SELECT `user_id` FROM `auth` WHERE `app_id`=? AND `auth_code` = ? AND `created_at` >= NOW() - INTERVAL 1 MINUTE LIMIT 1", client_id,code).Scan(&user_id)
		if(user_id<1){
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, "{\"status\": \"error\", \"message\": \"User Not Found\" }")
			return
		}

		

		var user_name,user_nick,user_image string
		db.QueryRow("SELECT `name`,`nick`,`image` FROM `user` WHERE `id` = ?", user_id).Scan(&user_name,&user_nick,&user_image)


		resp := Response{
			Status     : "success",
			AccessToken: "",
			IDToken:     "",
			ExpiresOn:   time.Now().UTC().Format(time.RFC3339),
			TokenType:   "Bearer",
			User: &User{
				UserID:    user_id,
				UserName:  user_name,
				UserNick:  user_nick,
				UserImage: user_image,
			},
		}

		write( "user", user_id, "redirect to:", redirect_uri )
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		
	})




	log.Fatal(http.ListenAndServe(":"+PORT, nil))
}





