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
type GlobalData struct {
 db *gocql.Session
 templates *template.Template
 store *sessions.CookieStore
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
type AppHandler struct {
	*GlobalData
	Handle func(*GlobalData , http.ResponseWriter , *http.Request)
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (user * UserContacts) DeleteContact(db *gocql.Session,id string) error{
	err := db.Query("delete from user_data where username = ? and contact_id = ?",user.UserName , id).Exec()
	return err

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
/*func (user * UserContacts) GetUserId(db *sql.DB) (error){
	var id int
	err := db.QueryRow("select id from users where username = ?",user.UserName).Scan(&id)
	user.Id = strconv.Itoa(id)
	return err

}*/
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (user * UserContacts) DeleteContactNumber(db *gocql.Session,id string , contactid string) error{
	err := db.Query("delete contact_phonenumbers[?] from user_data where username = ? and contact_id = ?",id ,user.UserName , contactid ).Exec()
	return err

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (user * UserContacts) GetUserContacts(context *GlobalData) error{

	var newcontact Contact
	rows := context.db.Query("select contact_id,contact_email,contact_fname,contact_lname,contact_phonenumbers from user_data where username= ?" , user.UserName)
	scanner :=rows.Iter().Scanner()
	for scanner.Next(){
		scanner.Scan(&newcontact.Id , &newcontact.Email, &newcontact.FirstName , &newcontact.LastName , &newcontact.PhoneNumbers)
		newcontact = StampContactId(newcontact)
		user.Contacts = append(user.Contacts, newcontact)
	}

	err := rows.Iter().Close()
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
	//err := user.GetUserId(context.db)

	err :=user.GetUserContacts(context)
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
	user.Password=""
	user.Contacts=[] Contact{}
	SaveUserSession(context ,"", w ,r)

	http.Redirect(w,r,"/home",http.StatusFound)
	return

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func StampContactId (contact  Contact) Contact{
	i :=0
	contact.PhoneNumbersStamped = []PhoneNum{}
	fmt.Println(len(contact.PhoneNumbers))
	contactid := contact.Id
	for i<len(contact.PhoneNumbers){
		numberid := i
		phonenumber := contact.PhoneNumbers[i]
		contact.PhoneNumbersStamped = append(contact.PhoneNumbersStamped , PhoneNum{ContactId:contactid , Id:numberid , Phonenumber:phonenumber})
		i++
	}
	return contact
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func (user * UserContacts) InsertNewContact(context *GlobalData , w http.ResponseWriter,r *http.Request) (Contact,error){

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
err := context.db.Query("insert into user_data (username ,contact_id , contact_email , contact_fname , contact_lname , contact_phonenumbers ) values(? , uuid() , ? , ? , ? , ? ) ", user.UserName, r.FormValue("email") , r.FormValue("first-name"), r.FormValue("last-name"), phonenumbers  ).Exec()
	if err !=nil {
		fmt.Println(err)
		return Contact{} , err
	}
	c = StampContactId(c)
	fmt.Println(c.PhoneNumbersStamped)
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
	err := user.DeleteContactNumber(context.db , r.FormValue("id") , r.FormValue("ID"))

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
	var databasePassword string

	err := context.db.Query("SELECT password FROM user_logins WHERE username=?", username).Scan( &databasePassword)
	fmt.Println(err)
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
	if err == gocql.ErrNotFound {
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
	case err == gocql.ErrNotFound:
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

	err := context.db.Query("SELECT password FROM user_logins WHERE username=?", username).Scan( &databasePassword)
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
	err :=context.db.Query("INSERT INTO user_logins(username, password) VALUES(?, ?)",username, hashedPassword).Exec()
	return err

}
///////////////////////////////////////////////////////////////////////////////////////////////////////
func main() {
	cluster := gocql.NewCluster("127.0.0.1")
	cluster.Keyspace = "address_book"
	Db, _ := cluster.CreateSession()
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