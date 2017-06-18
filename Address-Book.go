package main

import (
	"strconv"
	"net/http"
	"html/template"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
	"github.com/gorilla/sessions"
	gmux "github.com/gorilla/mux"
	"fmt"
	"github.com/codegangsta/negroni"

	"encoding/json"

)
type PhoneNum struct {
	Id int
	Phonenumber string

}
 type Contact struct{
	 Id int
	 FirstName string
	 LastName string
	 Email string
	 PhoneNumber []PhoneNum

 }
type UserContacts struct {
	UserName string
	Id string
	Contacts []Contact

}
type App struct {
 db *sql.DB
 err error
 templates *template.Template
 User UserContacts
}


func (MyApp *App) SignIn(w http.ResponseWriter, r *http.Request,username string ,password string ) {
	fmt.Println("logged in")
	// Grab from the database
	var databaseUsername string
	var databasePassword string

	MyApp.err = MyApp.db.QueryRow("SELECT username, password FROM users WHERE username=?", username).Scan(&databaseUsername, &databasePassword)
	if MyApp.err == sql.ErrNoRows {

		fmt.Println("no such user")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return

	} else if  MyApp.err != nil {

		http.Error(w,  MyApp.err.Error(), http.StatusInternalServerError)
		return
	}

	MyApp.err = bcrypt.CompareHashAndPassword([]byte(databasePassword), []byte(password))
	// If wrong password redirect to the login
	if  MyApp.err != nil {
		fmt.Println("wrong password")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	} else {
		fmt.Println("password match")
		// If the login succeeded
		session , _ := store.Get(r,"CurrentSession")
		session.Values["user"]=username
		session.Save(r,w)
		http.Redirect(w, r, "/userpage", 301)
		return
	}
}


func (MyApp *App)Register(w http.ResponseWriter, r *http.Request,username string ,password string ){

	fmt.Println("registered")
	var user string

	MyApp.err = MyApp.db.QueryRow("SELECT username FROM users WHERE username=?", username).Scan(&user)

	switch {
	// Username is available
	case MyApp.err == nil:
		fmt.Println("Username is not available")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	case MyApp.err == sql.ErrNoRows:
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			fmt.Println("Couldn't Incrypt")
			http.Error(w,err.Error(),http.StatusInternalServerError)
			return
		}

		_, err = MyApp.db.Exec("INSERT INTO users(username, password) VALUES(?, ?)", username, hashedPassword)
		if err != nil {
			http.Error(w,err.Error(),http.StatusInternalServerError)
			return
		}
		session , _ := store.Get(r,"CurrentSession")
		session.Values["user"]=username
		session.Save(r,w)
		http.Redirect(w, r, "/userpage", http.StatusFound)
		return
	case MyApp.err != nil:
		http.Error(w, "Server error, unable to create your account.", 500)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	default:
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}

}
func(MyApp *App) Login(w http.ResponseWriter, r *http.Request){

	username := r.FormValue("username")
	password := r.FormValue("password")

	if r.FormValue("register")!="" {
		MyApp.Register(w,r,username,password)
	}else if r.FormValue("login")!="" {
		MyApp.SignIn(w,r,username,password)
	}


}


func (MyApp *App) Delete(w http.ResponseWriter, r *http.Request){
	_ ,err := MyApp.db.Exec("delete from contact where contactID = ?",r.FormValue("id"))

	if err !=nil{
		fmt.Println("DB error")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Println("row Deleted")
}


func (MyApp *App) DeleteNum(w http.ResponseWriter, r *http.Request){
	fmt.Println(r.FormValue("id"))
	_ ,err := MyApp.db.Exec("delete from phonenumbers where id = ?",r.FormValue("id"))

	if err !=nil{
		fmt.Println("DB error")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Println("number Deleted")
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (MyApp *App) Check(w http.ResponseWriter, r *http.Request) {
	session , _ := store.Get(r,"CurrentSession")
	Usr :=session.Values["user"].(string)
	if Usr !="" {
		fmt.Println("lesa")
		http.Redirect(w,r,"/userpage",http.StatusFound)
		return
	}else {
		fmt.Println("logged out")
		http.Redirect(w,r,"/home",http.StatusFound)
		return
		}
	}

///////////////////////////////////////////////////////////////////////////////////////////////////////
func (MyApp *App) HomePage(w http.ResponseWriter, r *http.Request) {
	fmt.Println("home")
	if err := MyApp.templates.ExecuteTemplate(w, "index.html", nil); err != nil {
		fmt.Println("error home")
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (MyApp *App) UserPage(w http.ResponseWriter, r *http.Request){
	MyApp.User.Contacts = []Contact{}
	session , _ := store.Get(r,"CurrentSession")
	UsernameIn :=session.Values["user"]
	Username :=UsernameIn.(string)
	if Username==""{
		http.Redirect(w,r,"/home",http.StatusFound)
		return
	}
	MyApp.User.UserName =Username
	rows, err := MyApp.db.Query("select contactID,fname,lname,email,id,phonenumber from contact join`phonenumbers` on contact.contactID = phonenumbers.contact_id where userID= ( select id from users where username = ?)" , Username)
	if err!=nil{
		fmt.Println("DB error")
		http.Error(w,err.Error(),http.StatusInternalServerError)

	}

	var CurrentContact Contact
	var NewContact Contact
	var Phone PhoneNum

	for rows.Next() {

		rows.Scan(&NewContact.Id, &NewContact.FirstName, &NewContact.LastName , &NewContact.Email , &Phone.Id , &Phone.Phonenumber )

		if NewContact.Id!=CurrentContact.Id && CurrentContact.Id != 0{

			MyApp.User.Contacts = append(MyApp.User.Contacts, CurrentContact)
			CurrentContact = NewContact
			CurrentContact.PhoneNumber = append(CurrentContact.PhoneNumber, Phone)

		}else if CurrentContact.Id == 0{

			CurrentContact=NewContact
			CurrentContact.PhoneNumber=append(CurrentContact.PhoneNumber , Phone)
		}else{

			CurrentContact.PhoneNumber=append(CurrentContact.PhoneNumber , Phone)
		}

	}
	MyApp.User.Contacts = append(MyApp.User.Contacts, CurrentContact)
	if err := MyApp.templates.ExecuteTemplate(w, "userpage.html", MyApp.User); err != nil {
		http.Error(w, MyApp.err.Error(), http.StatusInternalServerError)
		fmt.Println("error")
		return

	}

}

/*func (MyApp *App) UsrPage(w http.ResponseWriter, r *http.Request) {
	//templates := template.Must(template.ParseFiles("userpage.html"))
	MyApp.User.Contacts = []Contact{}
	session , _ := store.Get(r,"CurrentSession")
	UsernameIn :=session.Values["user"]
	Username :=UsernameIn.(string)
	if Username==""{
		http.Redirect(w,r,"/home",http.StatusFound)
		return
	}

	MyApp.User.UserName =Username
	row := MyApp.db.QueryRow("select id from users where username= ?",Username)

	row.Scan(&MyApp.User.Id)
	 rows, err := MyApp.db.Query("select contactID,fname,lname,email from contact where userID= ?",MyApp.User.Id)
	if err!=nil{
		fmt.Println("DB error")
		http.Error(w,err.Error(),http.StatusInternalServerError)

	}

	for rows.Next() {
		var c Contact
		rows.Scan(&c.Id, &c.FirstName, &c.LastName , &c.Email )
		//fmt.Println(c.Id)
		res, err := MyApp.db.Query("select phonenumber,id from phonenumbers where contact_id= ?",c.Id)
		if err!=nil{
			fmt.Println("DB error")
			http.Error(w,err.Error(),http.StatusInternalServerError)

		}

		for res.Next() {
			Phone := PhoneNum{}
			res.Scan(&Phone.Phonenumber , &Phone.Id)
			c.PhoneNumber = append(c.PhoneNumber, Phone)

		}
		MyApp.User.Contacts = append(MyApp.User.Contacts, c)

	}


	if err := MyApp.templates.ExecuteTemplate(w, "userpage.html", MyApp.User); err != nil {
		http.Error(w, MyApp.err.Error(), http.StatusInternalServerError)
		fmt.Println("error")
		return

	}

}*/

func (MyApp *App) AddContact(w http.ResponseWriter, r *http.Request) {
	session , _ := store.Get(r,"CurrentSession")
	UsernameIn :=session.Values["user"]
	Username :=UsernameIn.(string)
	fmt.Println(Username)
	MyApp.User.UserName=Username
	row := MyApp.db.QueryRow("select Id from users where username =?",Username)
	row.Scan(&MyApp.User.Id)

	//Validate there are no empty fields

	if len(r.FormValue("first-name"))==0 || len(r.FormValue("last-name"))==0 || len(r.FormValue("email"))==0 {
		http.Error(w, "empty fields", http.StatusInternalServerError)
		return
	}
	//Start Transaction

	_ , err := MyApp.db.Exec("START TRANSACTION")
	if err!=nil {
		fmt.Println("bayza")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
		}
	fmt.Println(MyApp.User.Id)
	_, err = MyApp.db.Exec("insert into contact values(? ,? ,? ,? ,? ) ", nil, r.FormValue("first-name"), r.FormValue("last-name"), r.FormValue("email"), MyApp.User.Id)
	if err != nil {
		fmt.Println("error hena")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		MyApp.db.Exec("ROLLBACK")
		return
	}

	row = MyApp.db.QueryRow("select MAX(contactID) from contact")
	var id int
	row.Scan(&id)

	c := Contact{
		FirstName:r.FormValue("first-name"),
		LastName:r.FormValue("last-name"),
		Email:r.FormValue("email"),
		//PhoneNumber:r.FormValue("phone"),
	}
	i := 1
	for r.FormValue("phone" + strconv.Itoa(i)) != "" {
		str := r.FormValue("phone" + strconv.Itoa(i))
		_, err := MyApp.db.Exec("insert into phonenumbers values(?,?,?)", nil, str , id)
		if err != nil {
			MyApp.db.Exec("ROLLBACK")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		row := MyApp.db.QueryRow("select MAX(id) from phonenumbers")
		var id int
		row.Scan(&id)
		Phone := PhoneNum{Phonenumber:str , Id:id}
		c.PhoneNumber = append(c.PhoneNumber, Phone)
		i++
	}
	_ , err =MyApp.db.Exec("COMMIT")
	if err != nil{
		fmt.Println("bayza")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	MyApp.User.Contacts = append(MyApp.User.Contacts, c)
	fmt.Println("tmam")
	if err := json.NewEncoder(w).Encode(c); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}



func (MyApp *App) Logout(w http.ResponseWriter, r *http.Request){
	session , _ := store.Get(r,"CurrentSession")
	session.Values["user"]=""
	session.Save(r,w)

	http.Redirect(w,r,"/home",http.StatusFound)
	return

}

///////////////////////////////////////////////////////////////////////////////////////////////////////
var store = sessions.NewCookieStore([]byte("1819"))

func main() {

	MyApp :=App{}
	MyApp.templates =template.Must(template.ParseFiles("index.html" , "userpage.html"))
	MyApp.User = UserContacts{}
	MyApp.db , MyApp.err = sql.Open("mysql", "root:1819@tcp(127.0.0.1:3306)/my_add_bookDB")
	if MyApp.err != nil {
		panic(MyApp.err)
	}

	mux :=gmux.NewRouter()
	defer MyApp.db.Close()

	mux.HandleFunc("/", MyApp.Check)
	mux.HandleFunc("/home", MyApp.HomePage)
	mux.HandleFunc("/login", MyApp.Login).Methods("POST")
	mux.HandleFunc("/userpage", MyApp.UserPage).Methods("GET")
	mux.HandleFunc("/addcontact", MyApp.AddContact).Methods("POST")
	mux.HandleFunc("/logout", MyApp.Logout)
	mux.HandleFunc("/delete", MyApp.Delete)
	mux.HandleFunc("/deletenum", MyApp.DeleteNum)
	n:= negroni.Classic()
	n.UseHandler(mux)
	n.Run(":9000")
	//mux.ListenAndServe(":8080", nil)
}


