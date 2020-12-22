using Loginas.Models;
using Loginas.Repos;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Web;
using System.Web.Mvc;

namespace Loginas.Controllers
{
    public class HomeController : Controller
    {
        private DB_Entities _db = new DB_Entities();
        private GoogleAuthenticator gAuth = new GoogleAuthenticator();
        // GET: Home
        public ActionResult Index()
        {
            if (Session["idUser"] != null)
            {
                return View();
            }
            else
            {
                return RedirectToAction("Login");
            }
        }

        //GET: Register

        public ActionResult Register()
        {
            return View();
        }

        //POST: Register
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Register(User _user)
        {
            if (ModelState.IsValid)
            {
                var test= _db.Users.ToList();
                var check = _db.Users.FirstOrDefault(s => s.Email == _user.Email);
                if (check == null)
                {
                    _user.Password = GetSha256(_user.Password);
                    _db.Configuration.ValidateOnSaveEnabled = false;
                    _db.Users.Add(_user);
                    _db.SaveChanges();
                    return RedirectToAction("Index");
                }
                else
                {
                    ViewBag.error = "Email already exists";
                    return View();
                }


            }
            return View();


        }

        public ActionResult Login()
        {
            return View();
        }



        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(string email, string password,string pin)
        {
            if (ModelState.IsValid)
            {


                var f_password = GetSha256(password);
                var data = _db.Users.Where(s => s.Email.Equals(email) && s.Password.Equals(f_password)).ToList();
                if (data.Count() > 0)
                {
                    if (data.FirstOrDefault().GoogleAuth!=null)
                    {
                        if (!gAuth.GeneratePin(data.FirstOrDefault().GoogleAuth).Equals(pin))
                        {
                            ViewBag.error = "2F Auth failed";
                            return View();
                        }
                    }
                    //add session
                    Session["FullName"] = data.FirstOrDefault().FirstName + " " + data.FirstOrDefault().LastName;
                    Session["Email"] = data.FirstOrDefault().Email;
                    Session["idUser"] = data.FirstOrDefault().idUser;
                    return RedirectToAction("Index");
                }
                else
                {
                    ViewBag.error = "Wrong Email or Password";
                    return View();
                }
            }
            return View();
        }


        //Logout
        public ActionResult Logout()
        {
            Session.Clear();//remove session
            return RedirectToAction("Login");
        }

      
        public ActionResult GAuth()
        {
            if (Session["Email"]==null)
            {
                return RedirectToAction("Login");
            }
            string email = Session["Email"].ToString();
            var user =_db.Users.FirstOrDefault(s => s.Email == email);
            byte[] key;
            if (user.GoogleAuth==null)
            {
                RNG rng = new RNG();
                key= rng.GenerateRandomCryptographicBytes(256);
                _db.Database.ExecuteSqlCommand("Update Users set GoogleAuth={0} where Email={1}",key,user.Email);
            }
            else
            {
                key = user.GoogleAuth;
            }
            Session["GAuthUrl"]=gAuth.GenerateProvisioningUrl(email,key,500,500);

            return View();
        }

        
        public static string GetSha256(string str)
        {
            PasswordWithSaltHasher pwHasher = new PasswordWithSaltHasher();
            HashWithSaltResult hashResultSha256 = pwHasher.HashWithSalt(str, 64, SHA256.Create());

            return hashResultSha256.Digest;
        }

    }
}