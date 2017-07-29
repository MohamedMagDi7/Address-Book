package main

import (
	"strconv"
	"net/http"
	"html/template"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
	"github.com/gorilla/sessions"
	gmux "github.com/gorilla/mux"
	"fmt"
	"github.com/codegangsta/negroni"
	"github.com/gocql/gocql"
	"encoding/json"

	"regexp"
)

type UserSession struct{
	err string
	templates *template.Template
	store *sessions.CookieStore
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
type PhoneNum struct {
	Id int
	ContactId gocql.UUID
	Phonenumber string

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
type Contact struct{
	 Id gocql.UUID
	 FirstName string
	 LastName string
	 Email string
	 PhoneNumbersStamped []PhoneNum
	 PhoneNumbers []string

 }
///////////////////////////////////////////////////////////////////////////////////////////////////////
type UserContacts struct {
	UserName string
	Password string
	Err string
	Contacts []Contact


}
///////////////////////////////////////////////////////////////////////////////////////////////////////
type DatabaseSession struct {
 db *gocql.Session
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
type DBHandler struct {
	*DatabaseSession
	Handle func(  *DatabaseSession ,http.ResponseWriter , *http.Request )
}

func (dbHandler DBHandler) ServeHTTP(w http.ResponseWriter, r *http.Request ) {
	dbHandler.Handle(dbHandler.DatabaseSession, w, r )
	return
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
type AppHandler struct {
	Handle func(http.ResponseWriter , *http.Request )
}

func (appHandler AppHandler) ServeHTTP(w http.ResponseWriter, r *http.Request ) {
	appHandler.Handle( w, r )
	return
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (user * UserContacts) DeleteContact(databaseSession * DatabaseSession,id string) error{
	err := databaseSession.db.Query("delete from user_data where username = ? and contact_id = ?",user.UserName , id).Exec()
	return err

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (user * UserContacts) DeleteContactNumber(databaseSession * DatabaseSession,id string , contactid string) error{
	err := databaseSession.db.Query("delete contact_phonenumbers[?] from user_data where username = ? and contact_id = ?",id ,user.UserName , contactid ).Exec()
	return err

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (user * UserContacts) GetUserContacts(databaseSession * DatabaseSession) error{

	var newcontact Contact
	rows := databaseSession.db.Query("select contact_id,contact_email,contact_fname,contact_lname,contact_phonenumbers from user_data where username= ?" , user.UserName)
	scanner :=rows.Iter().Scanner()
	for scanner.Next(){
		scanner.Scan(&newcontact.Id , &newcontact.Email, &newcontact.FirstName , &newcontact.LastName , &newcontact.PhoneNumbers)
		newcontact.StampContactId()
		user.Contacts = append(user.Contacts, newcontact)
	}

	err := rows.Iter().Close()
	return err
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (context * UserSession) UserPage(databaseSession * DatabaseSession,w http.ResponseWriter, r *http.Request){
	username :=context.GetUserFromSession( r)
	if username==""{
		http.Redirect(w,r,"/home",http.StatusFound)
		return
	}
	user := UserContacts{Contacts:nil,Err:"",UserName:username}

	err :=user.GetUserContacts(databaseSession)
	if err!=nil{
		fmt.Println("DB error")
		http.Error(w,err.Error(),http.StatusInternalServerError)
		return
	}
	if err := context.templates.ExecuteTemplate(w, "userpage.html", user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		fmt.Println("error")
		return

	}

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (context *UserSession) AddContact(databaseSession * DatabaseSession, w http.ResponseWriter, r *http.Request) {
	Username :=context.GetUserFromSession(r)
	user := UserContacts{UserName:Username , Err:""}
	//Validate Inputs

	if r.FormValue("first-name")=="" || r.FormValue("last-name") == "" || r.FormValue("email") == "" {
		user.Err="Empty Fields"
		http.Redirect(w,r,"/userpage",301)
		return
	}

	if len(r.FormValue("first-name")) > 50 {
		user.Err="First Name is too long"
		http.Redirect(w,r,"/userpage",301)
		return
	}

	if len(r.FormValue("last-name")) > 50 {
		user.Err="Last Name is too long"
		http.Redirect(w,r,"/userpage",301)
		return
	}

	if len(r.FormValue("email")) > 50 {
		user.Err="email is too long"
		http.Redirect(w,r,"/userpage",301)
		return
	}
	fmt.Println(len(r.FormValue("email")))
	if len(r.FormValue("email")) < 7 {
		fmt.Println("here")
		user.Err="email is too short"
		http.Redirect(w,r,"/userpage",301)
		return
	}

	if validateEmail(r.FormValue("email")) == false {
		user.Err="Please enter a valid contact email!"
		http.Redirect(w,r,"/userpage",301)
		return
	}

	fmt.Println("before insert")
	c , err := user.InsertNewContact(databaseSession , w , r)
	if err !=nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(c); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (context *UserSession) Logout( w http.ResponseWriter, r *http.Request){
	context.SaveUserSession("", w ,r)
	http.Redirect(w,r,"/home",http.StatusFound)
	return

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (contact * Contact) StampContactId () {
	i :=0
	contact.PhoneNumbersStamped = []PhoneNum{}
	contactid := contact.Id
	for i<len(contact.PhoneNumbers){
		numberid := i
		phonenumber := contact.PhoneNumbers[i]
		contact.PhoneNumbersStamped = append(contact.PhoneNumbersStamped , PhoneNum{ContactId:contactid , Id:numberid , Phonenumber:phonenumber})
		i++
	}
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (user * UserContacts) InsertNewContact(databaseSession * DatabaseSession, w http.ResponseWriter,r *http.Request) (Contact,error){

var phonenumbers [] string

i := 1
for r.FormValue("phone" + strconv.Itoa(i)) != "" {
str := r.FormValue("phone" + strconv.Itoa(i))
phonenumbers = append(phonenumbers,str)
i++
}
	fmt.Println(phonenumbers)
c := Contact{
		FirstName:r.FormValue("first-name"),
		LastName:r.FormValue("last-name"),
		Email:r.FormValue("email"),
		PhoneNumbers:phonenumbers,
}

	fmt.Println("before query")
err := databaseSession.db.Query("insert into user_data (username ,contact_id , contact_email , contact_fname , contact_lname , contact_phonenumbers ) values(? , uuid() , ? , ? , ? , ? ) ", user.UserName, r.FormValue("email") , r.FormValue("first-name"), r.FormValue("last-name"), phonenumbers  ).Exec()
	if err !=nil {
		fmt.Println(err)
		return Contact{} , err
	}
	c.StampContactId()
	fmt.Println(c.PhoneNumbersStamped)
	user.Contacts = append(user.Contacts, c)
	return c , nil
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func(context * UserSession) Delete(databaseSession * DatabaseSession,w http.ResponseWriter, r *http.Request){
		username :=context.GetUserFromSession(r)
		user := UserContacts{UserName:username}
		err := user.DeleteContact(databaseSession, r.FormValue("id"))

		if err != nil {
			fmt.Println("DB error")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func(context * UserSession) DeleteNum(databaseSession * DatabaseSession,w http.ResponseWriter, r *http.Request){
	username :=context.GetUserFromSession(r)

		user := UserContacts{UserName:username}

		err := user.DeleteContactNumber(databaseSession, r.FormValue("id"), r.FormValue("ID"))

		if err != nil {
			fmt.Println("DB error")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (context *UserSession) Check(w http.ResponseWriter, r *http.Request) {

	user :=context.GetUserFromSession(r)
	if user !="" {
		http.Redirect(w,r,"/userpage",http.StatusFound)
		return
	}else {
		http.Redirect(w,r,"/home",http.StatusFound)
		return
		}
	}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (user *UserContacts) CheckUsernameExists(databaseSession * DatabaseSession ) error{
	var databasePassword string

	err := databaseSession.db.Query("SELECT password FROM user_logins WHERE username=?", user.UserName).Scan( &databasePassword)
	fmt.Println(err)
	return err
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (context  *UserSession) HomePage(w http.ResponseWriter, r *http.Request) {
	if err := context.templates.ExecuteTemplate(w, "index.html",context.err); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (context  *UserSession) SignIn(databaseSession * DatabaseSession, username string, password string , w http.ResponseWriter, r *http.Request ) {
	// Grab from the database
	var err error
	user :=UserContacts{UserName:username}
	var databasePassword string
	databasePassword, err = user.QueryUser(databaseSession)
	if err == gocql.ErrNotFound {
		//no such user
		context.err="Username doesn't exist"
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return

	} else if  err != nil {
		//Database Error
		context.err="Server Error"
		http.Error(w,  err.Error(), http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(databasePassword), []byte(password))
	// If wrong password redirect to the login
	if  err != nil {
		//Wrong Password
		context.err="Wrong Password"
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	} else {
		// If the login succeeded
		context.SaveUserSession(user.UserName,w,r)
		http.Redirect(w, r, "/userpage", 301)
		return
	}
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (context  *UserSession) Register(databaseSession * DatabaseSession,username string ,password string , w http.ResponseWriter, r *http.Request ){

	user := UserContacts{UserName:username}

	err :=user.CheckUsernameExists(databaseSession)
	switch {
	case err == nil:
		// Username is not available
		context.err="Please choose a different username"
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	case err == gocql.ErrNotFound:
		// Username is available
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			fmt.Println("Couldn't Incrypt")
			context.err="This Password is Not premitted"
			http.Error(w,err.Error(),http.StatusInternalServerError)
			return
		}

		err = user.InsertUser(databaseSession ,hashedPassword)
		if err != nil {
			http.Error(w,err.Error(),http.StatusInternalServerError)
			return
		}
		context.SaveUserSession(username,w,r)
		http.Redirect(w, r, "/userpage", http.StatusFound)
		return
	case err != nil:
		//Database Error
		http.Error(w, "Server error, unable to create your account.", 500)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	default:
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (context  *UserSession) Login(databaseSession * DatabaseSession, w http.ResponseWriter, r *http.Request){

	username := r.FormValue("username")
	password := r.FormValue("password")

	//Inputs Validation
	if len(username) > 50 {
		context.err="Username is too long"
		http.Redirect(w,r,"/home",301)
		return
	}
	if len(password) > 120 {

		context.err="Password is too long"
		http.Redirect(w,r,"/home",301)
		return
	}
	if username == "" {

		context.err="Please Enter a Username"
		http.Redirect(w,r,"/home",301)
		return
	}
	if password == "" {
		context.err="Please Enter a password"
		http.Redirect(w,r,"/home",301)
		return
	}
	if validateEmail(username) == false {
		context.err="Please Enter a valid Username"
		http.Redirect(w,r,"/home",301)
		return
	}

	if r.FormValue("register")!="" {
		context.Register(databaseSession , username ,password ,w,r)
	}else if r.FormValue("login")!="" {
		context.SignIn(databaseSession , username ,password ,w,r)
	}


}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (user * UserContacts) QueryUser(databaseSession * DatabaseSession) (string,error){
	var databasePassword string

	err := databaseSession.db.Query("SELECT password FROM user_logins WHERE username=?", user.UserName).Scan( &databasePassword)
	return databasePassword,err
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (context * UserSession) SaveUserSession( username string , w http.ResponseWriter , r *http.Request){
	session , _ := context.store.Get(r,"CurrentSession")
	session.Values["user"]=username
	session.Save(r,w)
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (context * UserSession) GetUserFromSession(r *http.Request) string{

	session , _ := context.store.Get(r,"CurrentSession")

	user , ok := session.Values["user"].(string)
	if ok {
		return user
	}else {
		return ""
	}

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (user * UserContacts) InsertUser(databaseSession * DatabaseSession, hashedPassword []byte) error{
	err :=databaseSession.db.Query("INSERT INTO user_logins(username, password) VALUES(?, ?)",user.UserName, hashedPassword).Exec()
	return err

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func main() {

	db, err := StartDBConnection("127.0.0.1" , "address_book")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	databaseSession := &DatabaseSession{db:db}

	context := &UserSession{
	templates:template.Must(template.ParseFiles("index.html" , "userpage.html")),
	store :sessions.NewCookieStore([]byte("1819")),
	err:""}
	mux :=gmux.NewRouter()


	mux.Handle("/", AppHandler{context.Check})
	mux.Handle("/home", AppHandler{ context.HomePage })
	mux.Handle("/login",DBHandler{databaseSession , context.Login}).Methods("POST")
	mux.Handle("/userpage", DBHandler{databaseSession , context.UserPage}).Methods("GET")
	mux.Handle("/addcontact",DBHandler{databaseSession , context.AddContact}).Methods("POST")
	mux.Handle("/logout",AppHandler{context.Logout})
	mux.Handle("/delete", DBHandler{databaseSession ,context.Delete})
	mux.Handle("/deletenum", DBHandler{databaseSession ,context.DeleteNum})
	n:= negroni.Classic()
	n.UseHandler(mux)
	n.Run(":8000")
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func validateEmail(email string) bool {
	Re := regexp.MustCompile(`.`)
	return Re.MatchString(email)
}

func StartDBConnection(host string , keyspace string ) (*gocql.Session , error){
	cluster := gocql.NewCluster(host)
	cluster.Keyspace = keyspace
	return cluster.CreateSession()
}
