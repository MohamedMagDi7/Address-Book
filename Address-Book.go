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

	"regexp"
)

type UserSession struct{
	err string
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
type PhoneNum struct {
	Id int64
	Phonenumber string

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
type Contact struct{
	 Id int
	 FirstName string
	 LastName string
	 Email string
	 PhoneNumber []PhoneNum

 }
///////////////////////////////////////////////////////////////////////////////////////////////////////
type UserContacts struct {
	UserName string
	Id string
	Password string
	Err string
	Contacts []Contact


}
///////////////////////////////////////////////////////////////////////////////////////////////////////
type GlobalData struct {
 db *sql.DB
 templates *template.Template
 store *sessions.CookieStore
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
type AppHandler struct {
	*GlobalData
	Handle func(*GlobalData , http.ResponseWriter , *http.Request)
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (user * UserContacts) DeleteContact(db *sql.DB,id string) error{
	_ ,err := db.Exec("delete from contact where contactID = ?",id)
	return err

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (user * UserContacts) GetUserId(db *sql.DB) (error){
	var id int
	err := db.QueryRow("select id from users where username = ?",user.UserName).Scan(&id)
	user.Id = strconv.Itoa(id)
	return err

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (user * UserContacts) DeleteContactNumber(db *sql.DB,id string) error{
	_ ,err := db.Exec("delete from phonenumbers where id = ?",id)
	return err

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (user * UserContacts) GetUserContacts(context *GlobalData) error{
	rows, err := context.db.Query("select contactID,fname,lname,email,id,phonenumber from contact join`phonenumbers` on contact.contactID = phonenumbers.contact_id where userID= ?" , user.Id)
	var currentcontact Contact
	var newcontact Contact
	var phone PhoneNum

	for rows.Next() {

		rows.Scan(&newcontact.Id, &newcontact.FirstName, &newcontact.LastName , &newcontact.Email , &phone.Id , &phone.Phonenumber )

		if newcontact.Id!=currentcontact.Id && currentcontact.Id != 0{

			user.Contacts = append(user.Contacts, currentcontact)
			currentcontact = newcontact


		}else if currentcontact.Id == 0{

			currentcontact=newcontact

		}
		currentcontact.PhoneNumber = append(currentcontact.PhoneNumber, phone)
	}
	user.Contacts = append(user.Contacts, currentcontact)
	return err
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func  (user  *UserContacts) UserPage(context *GlobalData,w http.ResponseWriter, r *http.Request){
	username :=GetUserFromSession(context, r)
	user.Contacts= nil
	if username==""{
		http.Redirect(w,r,"/home",http.StatusFound)
		return
	}
	user.UserName=username
	err := user.GetUserId(context.db)

	err =user.GetUserContacts(context)
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
func (user  *UserContacts) AddContact(context *GlobalData, w http.ResponseWriter, r *http.Request) {
	user.Err=""
	Username :=GetUserFromSession(context,r)
	user.UserName=Username
	fmt.Println("Add contact")
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


	c , err := user.InsertNewContact(context , w , r)
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
func (user  *UserContacts)  Logout(context *GlobalData,w http.ResponseWriter, r *http.Request){
	user.UserName=""
	user.Id=""
	user.Password=""
	user.Contacts=[] Contact{}
	SaveUserSession(context ,"", w ,r)

	http.Redirect(w,r,"/home",http.StatusFound)
	return

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (user * UserContacts) InsertNewContact(context *GlobalData , w http.ResponseWriter,r *http.Request) (Contact,error){
//Start Transaction

_ , err := context.db.Exec("START TRANSACTION")
if err!=nil {
return Contact{},err
}

res, _err := context.db.Exec("insert into contact values(? ,? ,? ,? ,? ) ", nil, r.FormValue("first-name"), r.FormValue("last-name"), r.FormValue("email"), user.Id)
if _err != nil {
	context.db.Exec("ROLLBACK")
	return Contact{},err
}
	id , _ := res.LastInsertId()

c := Contact{
FirstName:r.FormValue("first-name"),
LastName:r.FormValue("last-name"),
Email:r.FormValue("email"),
//PhoneNumber:r.FormValue("phone"),
}
i := 1
for r.FormValue("phone" + strconv.Itoa(i)) != "" {
str := r.FormValue("phone" + strconv.Itoa(i))
res , err := context.db.Exec("insert into phonenumbers values(?,?,?)", nil, str , id)
if err != nil {
	context.db.Exec("ROLLBACK")
	return Contact{},err
}
id , _ := res.LastInsertId()
Phone := PhoneNum{Phonenumber:str , Id:id}
c.PhoneNumber = append(c.PhoneNumber, Phone)
i++
}
_ , err =context.db.Exec("COMMIT")
if err != nil {
	fmt.Println("bayza")
	return Contact{}, err
}
	user.Contacts = append(user.Contacts, c)
return c , nil
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (appHandler AppHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	appHandler.Handle(appHandler.GlobalData , w, r)
	return
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (user  *UserContacts) Delete(context *GlobalData,w http.ResponseWriter, r *http.Request){
	err := user.DeleteContact(context.db,r.FormValue("id"))

	if err !=nil{
		fmt.Println("DB error")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (user  *UserContacts)  DeleteNum(context *GlobalData,w http.ResponseWriter, r *http.Request){
	err := user.DeleteContactNumber(context.db , r.FormValue("id"))

	if err !=nil{
		fmt.Println("DB error")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func  Check(context *GlobalData, w http.ResponseWriter, r *http.Request) {

	user :=GetUserFromSession(context , r)
	if user !="" {
		http.Redirect(w,r,"/userpage",http.StatusFound)
		return
	}else {
		http.Redirect(w,r,"/home",http.StatusFound)
		return
		}
	}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func CheckUsernameExists(context *GlobalData , username string) error{
	var userName string
	_,err := context.db.Query("SELECT username FROM users WHERE username=?", userName)
	return err
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (usersession  *UserSession) HomePage(context *GlobalData, w http.ResponseWriter, r *http.Request) {
	fmt.Println(usersession.err)
	if err := context.templates.ExecuteTemplate(w, "index.html",usersession.err); err != nil {
		fmt.Println("error home")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (usersession  *UserSession) SignIn(context *GlobalData, username string, password string , w http.ResponseWriter, r *http.Request ) {
	// Grab from the database
	var err error
	var databasePassword string
	databasePassword, err = QueryUser(context, username)
	if err == sql.ErrNoRows {
		//no such user
		usersession.err="Username doesn't exist"
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return

	} else if  err != nil {
		//Database Error
		usersession.err="Server Error"
		http.Error(w,  err.Error(), http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(databasePassword), []byte(password))
	// If wrong password redirect to the login
	if  err != nil {
		//Wrong Password
		usersession.err="Wrong Password"
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	} else {
		// If the login succeeded
		SaveUserSession(context,username,w,r)
		http.Redirect(w, r, "/userpage", 301)
		return
	}
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (usersession  *UserSession) Register(context *GlobalData,username string ,password string , w http.ResponseWriter, r *http.Request ){



	err :=CheckUsernameExists(context , username)
	switch {
	case err == nil:
		// Username is not available
		usersession.err="Please choose a different username"
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	case err == sql.ErrNoRows:
		// Username is available
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			fmt.Println("Couldn't Incrypt")
			usersession.err="This Password is Not premitted"
			http.Error(w,err.Error(),http.StatusInternalServerError)
			return
		}

		err = InsertUser(context,username,hashedPassword)
		if err != nil {
			http.Error(w,err.Error(),http.StatusInternalServerError)
			return
		}
		SaveUserSession(context,username,w,r)
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
func (usersession  *UserSession)Login(context *GlobalData, w http.ResponseWriter, r *http.Request){

	username := r.FormValue("username")
	password := r.FormValue("password")

	//Inputs Validation
	if len(username) > 50 {
		usersession.err="Username is too long"
		http.Redirect(w,r,"/home",301)
		return
	}
	if len(password) > 120 {

		usersession.err="Password is too long"
		http.Redirect(w,r,"/home",301)
		return
	}
	if username == "" {

		usersession.err="Please Enter a Username"
		http.Redirect(w,r,"/home",301)
		return
	}
	if password == "" {
		usersession.err="Please Enter a password"
		http.Redirect(w,r,"/home",301)
		return
	}
	if validateEmail(username) == false {
		usersession.err="Please Enter a valid Username"
		http.Redirect(w,r,"/home",301)
		return
	}

	if r.FormValue("register")!="" {
		usersession.Register(context , username ,password ,w,r)
	}else if r.FormValue("login")!="" {
		usersession.SignIn(context , username ,password ,w,r)
	}


}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func Write (w http.ResponseWriter, r *http.Request , next http.HandlerFunc){
//fmt.Println("I am in middleWare")
	next(w,r)
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func QueryUser(context *GlobalData , username string) (string,error){
	var databasePassword string

	err := context.db.QueryRow("SELECT password FROM users WHERE username=?", username).Scan( &databasePassword)

	return databasePassword,err
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func  SaveUserSession(context *GlobalData, username string , w http.ResponseWriter , r *http.Request){
	session , _ := context.store.Get(r,"CurrentSession")
	session.Values["user"]=username
	session.Save(r,w)
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func GetUserFromSession(context *GlobalData,r *http.Request) string{
	session , _ := context.store.Get(r,"CurrentSession")
	user :=session.Values["user"].(string)
	return user
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func InsertUser(context *GlobalData, username string, hashedPassword []byte) error{
	_, err :=context.db.Exec("INSERT INTO users(username, password) VALUES(?, ?)",username, hashedPassword)
	return err

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func main() {
	Db ,_ := sql.Open("mysql", "root:1819@tcp(127.0.0.1:3306)/my_add_bookDB")
	Context := &GlobalData{db:Db ,
	templates:template.Must(template.ParseFiles("index.html" , "userpage.html")),
	store :sessions.NewCookieStore([]byte("1819")) }
	User := & UserContacts{}
	Usersession := &UserSession{err:""}
	mux :=gmux.NewRouter()
	defer Context.db.Close()

	mux.Handle("/", AppHandler{Context,Check})
	mux.Handle("/home", AppHandler{Context,Usersession.HomePage})
	mux.Handle("/login",AppHandler{Context,Usersession.Login}).Methods("POST")
	mux.Handle("/userpage", AppHandler{Context,User.UserPage}).Methods("GET")
	mux.Handle("/addcontact",AppHandler{Context, User.AddContact}).Methods("POST")
	mux.Handle("/logout",AppHandler{Context, User.Logout})
	mux.Handle("/delete", AppHandler{Context,User.Delete})
	mux.Handle("/deletenum", AppHandler{Context, User.DeleteNum})
	n:= negroni.Classic()
	n.Use(negroni.HandlerFunc(Write))
	n.UseHandler(mux)
	n.Run(":9000")
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func validateEmail(email string) bool {
	Re := regexp.MustCompile(`.`)
	return Re.MatchString(email)
}