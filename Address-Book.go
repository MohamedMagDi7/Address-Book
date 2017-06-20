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
	Contacts []Contact

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
type GlobalData struct {
 db *sql.DB
 err error
 templates *template.Template
 store *sessions.CookieStore
 User UserContacts
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
type AppHandler struct {
	*GlobalData
	Handle func(*GlobalData , http.ResponseWriter , *http.Request)
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func SaveUserSession(Context *GlobalData,w http.ResponseWriter , r *http.Request){
	session , _ := Context.store.Get(r,"CurrentSession")
	session.Values["user"]=Context.User.UserName
	session.Save(r,w)
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func GetUserFromSession(Context *GlobalData,r *http.Request) string{
	session , _ := Context.store.Get(r,"CurrentSession")
	Usr :=session.Values["user"].(string)
	return Usr
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func InsertUser(Context *GlobalData, hashedPassword []byte) error{
_, err :=Context.db.Exec("INSERT INTO users(username, password) VALUES(?, ?)", Context.User.UserName, hashedPassword)
return err

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func DeleteUser(db *sql.DB,id string) error{
	_ ,err := db.Exec("delete from contact where contactID = ?",id)
	return err

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func GetUserId(db *sql.DB,username string) (int,error){
	var id int
	err := db.QueryRow("select id from users where username = ?",username).Scan(&id)
	return id,err

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func DeleteContactNumber(db *sql.DB,id string) error{
	_ ,err := db.Exec("delete from phonenumbers where id = ?",id)
	return err

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func CheckUsernameExists(Context *GlobalData) error{
	var user string

	err := Context.db.QueryRow("SELECT username FROM users WHERE username=?", Context.User.UserName).Scan(&user)
	return err
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func GetUserContacts(Context *GlobalData) error{
	rows, err := Context.db.Query("select contactID,fname,lname,email,id,phonenumber from contact join`phonenumbers` on contact.contactID = phonenumbers.contact_id where userID= ?" , Context.User.Id)
	var CurrentContact Contact
	var NewContact Contact
	var Phone PhoneNum

	for rows.Next() {

		rows.Scan(&NewContact.Id, &NewContact.FirstName, &NewContact.LastName , &NewContact.Email , &Phone.Id , &Phone.Phonenumber )

		if NewContact.Id!=CurrentContact.Id && CurrentContact.Id != 0{

			Context.User.Contacts = append(Context.User.Contacts, CurrentContact)
			CurrentContact = NewContact


		}else if CurrentContact.Id == 0{

			CurrentContact=NewContact

		}
		CurrentContact.PhoneNumber = append(CurrentContact.PhoneNumber, Phone)
	}
	Context.User.Contacts = append(Context.User.Contacts, CurrentContact)
	return err
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func QueryUser(Context *GlobalData) (string,error){
	var databaseUsername string
	var databasePassword string

	err := Context.db.QueryRow("SELECT username, password FROM users WHERE username=?", Context.User.UserName).Scan(&databaseUsername, &databasePassword)

	return databasePassword,err
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func InsertNewContact(Context *GlobalData, w http.ResponseWriter,r *http.Request) (Contact,error){
//Start Transaction

_ , err := Context.db.Exec("START TRANSACTION")
if err!=nil {
return Contact{},err
}
fmt.Println(Context.User.Id)
_, err = Context.db.Exec("insert into contact values(? ,? ,? ,? ,? ) ", nil, r.FormValue("first-name"), r.FormValue("last-name"), r.FormValue("email"), Context.User.Id)
if err != nil {
	Context.db.Exec("ROLLBACK")
	return Contact{},err
}

row := Context.db.QueryRow("select MAX(contactID) from contact")
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
_, err := Context.db.Exec("insert into phonenumbers values(?,?,?)", nil, str , id)
if err != nil {
	Context.db.Exec("ROLLBACK")
	return Contact{},err
}
row := Context.db.QueryRow("select MAX(id) from phonenumbers")
var id int
row.Scan(&id)
Phone := PhoneNum{Phonenumber:str , Id:id}
c.PhoneNumber = append(c.PhoneNumber, Phone)
i++
}
_ , err =Context.db.Exec("COMMIT")
if err != nil {
	fmt.Println("bayza")
	return Contact{}, err
}
Context.User.Contacts = append(Context.User.Contacts, c)
return c , nil
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (AppHand AppHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	AppHand.Handle(AppHand.GlobalData , w, r)
	return
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func  SignIn(Context *GlobalData, w http.ResponseWriter, r *http.Request ) {
	// Grab from the database
	var databasePassword string
	databasePassword, Context.err = QueryUser(Context)
	if Context.err == sql.ErrNoRows {
		//no such user
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return

	} else if  Context.err != nil {
		//Database Error
		http.Error(w,  Context.err.Error(), http.StatusInternalServerError)
		return
	}

	Context.err = bcrypt.CompareHashAndPassword([]byte(databasePassword), []byte(Context.User.Password))
	// If wrong password redirect to the login
	if  Context.err != nil {
		//Wrong Password
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	} else {
		// If the login succeeded
		SaveUserSession(Context,w,r)
		http.Redirect(w, r, "/userpage", 301)
		return
	}
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func Register(Context *GlobalData, w http.ResponseWriter, r *http.Request ){



	 Context.err =CheckUsernameExists(Context)

	switch {
	case Context.err == nil:
		// Username is not available
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	case Context.err == sql.ErrNoRows:
		// Username is available
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(Context.User.Password), bcrypt.DefaultCost)
		if err != nil {
			fmt.Println("Couldn't Incrypt")
			http.Error(w,err.Error(),http.StatusInternalServerError)
			return
		}

		err = InsertUser(Context,hashedPassword)
		if err != nil {
			http.Error(w,err.Error(),http.StatusInternalServerError)
			return
		}
		SaveUserSession(Context,w,r)
		http.Redirect(w, r, "/userpage", http.StatusFound)
		return
	case Context.err != nil:
		//Database Error
		http.Error(w, "Server error, unable to create your account.", 500)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	default:
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func Login(Context *GlobalData, w http.ResponseWriter, r *http.Request){

	username := r.FormValue("username")
	password := r.FormValue("password")

	Context.User.UserName=username
	Context.User.Password=password
	if r.FormValue("register")!="" {
		Register(Context ,w,r)
	}else if r.FormValue("login")!="" {
		SignIn(Context ,w,r)
	}


}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func Delete(Context *GlobalData,w http.ResponseWriter, r *http.Request){
	err := DeleteUser(Context.db,r.FormValue("id"))

	if err !=nil{
		fmt.Println("DB error")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func DeleteNum(Context *GlobalData,w http.ResponseWriter, r *http.Request){
	err := DeleteContactNumber(Context.db , r.FormValue("id"))

	if err !=nil{
		fmt.Println("DB error")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func  Check(Context *GlobalData, w http.ResponseWriter, r *http.Request) {

	Usr :=GetUserFromSession(Context , r)
	if Usr !="" {
		http.Redirect(w,r,"/userpage",http.StatusFound)
		return
	}else {
		http.Redirect(w,r,"/home",http.StatusFound)
		return
		}
	}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func HomePage(Context *GlobalData, w http.ResponseWriter, r *http.Request) {

	if err := Context.templates.ExecuteTemplate(w, "index.html", nil); err != nil {
		fmt.Println("error home")
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func  UserPage(Context *GlobalData,w http.ResponseWriter, r *http.Request){
	Context.User.Contacts = []Contact{}
	Username :=GetUserFromSession(Context, r)
	if Username==""{
		http.Redirect(w,r,"/home",http.StatusFound)
		return
	}
	id , err := GetUserId(Context.db , Username)
	Context.User.UserName =Username
	Context.User.Id=strconv.Itoa(id)
	err =GetUserContacts(Context)
	if err!=nil{
		fmt.Println("DB error")
		http.Error(w,err.Error(),http.StatusInternalServerError)
		return
	}

	if err := Context.templates.ExecuteTemplate(w, "userpage.html", Context.User); err != nil {
		http.Error(w, Context.err.Error(), http.StatusInternalServerError)
		fmt.Println("error")
		return

	}

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func  AddContact(Context *GlobalData,w http.ResponseWriter, r *http.Request) {

	Username :=GetUserFromSession(Context,r)
	Context.User.UserName=Username
	//Validate there are no empty fields

	if len(r.FormValue("first-name"))==0 || len(r.FormValue("last-name"))==0 || len(r.FormValue("email"))==0 {
		http.Error(w, "empty fields", http.StatusInternalServerError)
		return
	}

	c , err := InsertNewContact(Context,w , r)
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
func  Logout(Context *GlobalData,w http.ResponseWriter, r *http.Request){
	Context.User=UserContacts{}
	SaveUserSession(Context , w ,r)

	http.Redirect(w,r,"/home",http.StatusFound)
	return

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func Write (w http.ResponseWriter, r *http.Request , next http.HandlerFunc){
//fmt.Println("I am in middleWare")
	next(w,r)
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func main() {
	Db ,_ := sql.Open("mysql", "root:1819@tcp(127.0.0.1:3306)/my_add_bookDB")
	Context := &GlobalData{db:Db ,
	templates:template.Must(template.ParseFiles("index.html" , "userpage.html")),
	store :sessions.NewCookieStore([]byte("1819")) }

	mux :=gmux.NewRouter()
	//defer MyApp.db.Close()

	mux.Handle("/", AppHandler{Context,Check})
	mux.Handle("/home", AppHandler{Context,HomePage})
	mux.Handle("/login",AppHandler{Context,Login}).Methods("POST")
	mux.Handle("/userpage", AppHandler{Context,UserPage}).Methods("GET")
	mux.Handle("/addcontact",AppHandler{Context, AddContact}).Methods("POST")
	mux.Handle("/logout",AppHandler{Context, Logout})
	mux.Handle("/delete", AppHandler{Context,Delete})
	mux.Handle("/deletenum", AppHandler{Context,DeleteNum})
	n:= negroni.Classic()
	n.Use(negroni.HandlerFunc(Write))
	n.UseHandler(mux)
	n.Run(":9000")
	//mux.ListenAndServe(":8080", nil)
}


/*func OpenDB() (*sql.DB ,error) {
	db ,err := sql.Open("mysql", "root:1819@tcp(127.0.0.1:3306)/my_add_bookDB")
	return db , err


}*/