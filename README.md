# SQL Injection

SQL injection is a code injection technique, used to attack data-driven applications, in which malicious SQL statements are inserted into an entry field for execution (e.g. to dump the database contents to the attacker). SQL injection must exploit a security vulnerability in an application's software, for example, when user input is either incorrectly filtered for string literal escape characters embedded in SQL statements or user input is not strongly typed and unexpectedly executed. SQL injection is mostly known as an attack vector for websites but can be used to attack any type of SQL database. (wikipedia). It is used in database database technologies. There have been create basic. We will be using php web application to demonstrate sql injection. 

## Demo
* Video clip on demonstration: https://youtu.be/KH_4s2WVDK0

## Prerequisites

You must have following programs/packages in order to run this project.

* Apache: 2.4.46
* PHP: 7.2.33 
* MariaDB: 10.4.14
* phpMyAdmin: 5.0.2

Note: the XAMPP server include all above mentioned technologies. https://www.apachefriends.org/download.html 

## Simple Login Development Approach

A simple php and MySQL based web application is developed which has registration, login, dashboard and logout. The authentication is very common in modern web application. It is a security mechanism that is used to restrict unauthorized access to member-only areas and tools on a site.

In this section we'll build a registration system that allows users to create a new account by filling out a web form. But, first we need to create a table that will hold all the user data.

### Step 1: Creating the database table

```
CREATE TABLE users (
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```
### Step 2: Creating the config script

After creating the table, we need create a PHP script in order to connect to the MySQL database server. Let's create a file named "config.php" and put the following code inside it.

```
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */

define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', '');
define('DB_NAME', 'sql_injection');
 
/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
 
// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>
```
Note: Replace the credentials according to your MySQL server setting before testing this code, for example, replace the database name 'sql_injection' with your own database name, replace username 'root' with your own database username, specify database password if there's any.

### Step 3: Creating the registration module

Let's create another PHP file "register.php" and put the following example code in it. This example code will create a web form that allows user to register themselves.

This script will also generate errors if a user tries to submit the form without entering any value, or if username entered by the user is already taken by another user.

```
<?php
/* Include config file */
require_once "config.php";

/* Define variables and initialize with empty values */
$username = $password = $confirm_password = "";
$username_err = $password_err = $confirm_password_err = "";

/* Processing form data when form is submitted */
if ($_SERVER["REQUEST_METHOD"] == "POST")
{

    /* Validate username */
    if (empty(trim($_POST["username"])))
    {
        $username_err = "Please enter a username.";
    }
    else
    {
        /* Prepare a select statement */
        $sql = "SELECT id FROM users WHERE username = ?";

        if ($stmt = mysqli_prepare($link, $sql))
        {
            /* Bind variables to the prepared statement as parameters */
            mysqli_stmt_bind_param($stmt, "s", $param_username);

            /* Set parameters */
            $param_username = trim($_POST["username"]);

            /* Attempt to execute the prepared statement */
            if (mysqli_stmt_execute($stmt))
            {
                /* store result */
                mysqli_stmt_store_result($stmt);

                if (mysqli_stmt_num_rows($stmt) == 1)
                {
                    $username_err = "This username is already taken.";
                }
                else
                {
                    $username = trim($_POST["username"]);
                }
            }
            else
            {
                echo "Oops! Something went wrong. Please try again later.";
            }

            /* Close statement */
            mysqli_stmt_close($stmt);
        }
    }

    /* Validate password */
    if (empty(trim($_POST["password"])))
    {
        $password_err = "Please enter a password.";
    }
    elseif (strlen(trim($_POST["password"])) < 6)
    {
        $password_err = "Password must have atleast 6 characters.";
    }
    else
    {
        $password = trim($_POST["password"]);
    }

    /* Validate confirm password */
    if (empty(trim($_POST["confirm_password"])))
    {
        $confirm_password_err = "Please confirm password.";
    }
    else
    {
        $confirm_password = trim($_POST["confirm_password"]);
        if (empty($password_err) && ($password != $confirm_password))
        {
            $confirm_password_err = "Password did not match.";
        }
    }

    /* Check input errors before inserting in database */
    if (empty($username_err) && empty($password_err) && empty($confirm_password_err))
    {

        /* Prepare an insert statement */
        $sql = "INSERT INTO users (username, password) VALUES (?, ?)";

        if ($stmt = mysqli_prepare($link, $sql))
        {
            /* Bind variables to the prepared statement as parameters */
            mysqli_stmt_bind_param($stmt, "ss", $param_username, $param_password);

            /* Set parameters */
            $param_username = $username;
            $param_password = md5($password);
            /* Creates a password hash
            Attempt to execute the prepared statement */
            if (mysqli_stmt_execute($stmt))
            {
                /* Redirect to login page */
                header("location: login.php");
            }
            else
            {
                echo "Something went wrong. Please try again later.";
            }

            /* Close statement */
            mysqli_stmt_close($stmt);
        }
    }

    /* Close connection */
    mysqli_close($link);
}
?>
 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sign Up</title>
    <link rel="stylesheet" href="assets/bootstrap.css">
    <style type="text/css">
        body{ font: 14px sans-serif; }
        .wrapper{ width: 350px; padding: 20px; }
    </style>
</head>
<body>
    <div class="wrapper">
        <h2>Sign Up</h2>
        <p>Please fill this form to create an account.</p>
        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <div class="form-group <?php echo (!empty($username_err)) ? 'has-error' : ''; ?>">
                <label>Username</label>
                <input type="text" name="username" autocomplete="off" class="form-control" value="<?php echo $username; ?>">
                <span class="help-block"><?php echo $username_err; ?></span>
            </div>    
            <div class="form-group <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">
                <label>Password</label>
                <input type="password" name="password" autocomplete="off" class="form-control" value="<?php echo $password; ?>">
                <span class="help-block"><?php echo $password_err; ?></span>
            </div>
            <div class="form-group <?php echo (!empty($confirm_password_err)) ? 'has-error' : ''; ?>">
                <label>Confirm Password</label>
                <input type="password" name="confirm_password" autocomplete="off" class="form-control" value="<?php echo $confirm_password; ?>">
                <span class="help-block"><?php echo $confirm_password_err; ?></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Submit">
                <input type="reset" class="btn btn-default" value="Reset">
            </div>
            <p>Already have an account? <a href="login.php">Login here</a>.</p>
        </form>
    </div>    
</body>
</html>
```

### Step 4: Creating the login module

In this section we'll create a login form where user can enter their username and password. When user submit the form these inputs will be verified against the credentials stored in the database, if the username and password match, the user is authorized and granted access to the site, otherwise the login attempt will be rejected.

Let's create a file named "login.php" and place the following code inside it.

```
<?php
/* Initialize the session */
session_start();

/* Check if the user is already logged in, if yes then redirect him to welcome page */
if (isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true)
{
    header("location: welcome.php");
    exit;
}

/* Include config file */
require_once "config.php";

/* Define variables and initialize with empty values */
$username = $password = "";
$username_err = $password_err = "";

/* Processing form data when form is submitted */
if ($_SERVER["REQUEST_METHOD"] == "POST")
{

    /* Check if username is empty */
    if (empty(trim($_POST["username"])))
    {
        $username_err = "Please enter username.";
    }
    else
    {
        $username = trim($_POST["username"]);
    }

    /* Check if password is empty */
    if (empty(trim($_POST["password"])))
    {
        $password_err = "Please enter your password.";
    }
    else
    {
        $password = trim($_POST["password"]);
    }

    /* Validate credentials */
    if (empty($username_err) && empty($password_err))
    {
        /* Prepare a sql query statement */
        $sql = "SELECT id, username FROM users WHERE username = '$username' and password = md5('$password')";

        $result = mysqli_query($link, $sql);

        if (mysqli_num_rows($result) > 0)
        {
            session_start();

            /* Store data in session variables */
            $_SESSION["loggedin"] = true;
            $_SESSION["id"] = $id;
            $_SESSION["username"] = $username;

            /* Redirect user to welcome page */
            header("location: welcome.php");
        }
        else
        {
            /* Display an error message if there is no row selected. */
            $password_err = "The password you entered was not valid.";
        }
        /* Close statement */
        mysqli_close($link);
    }
}
?>
 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="assets/bootstrap.css">
    <style type="text/css">
        body{ font: 14px sans-serif; }
        .wrapper{ width: 350px; padding: 20px; }
    </style>
</head>
<body>
    <div class="wrapper">
        <h2>Login</h2>
        <p>Please fill in your credentials to login.</p>
        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <div class="form-group <?php echo (!empty($username_err)) ? 'has-error' : ''; ?>">
                <label>Username</label>
                <input type="text" name="username" autocomplete="off" class="form-control" value="<?php echo $username; ?>">
                <span class="help-block"><?php echo $username_err; ?></span>
            </div>    
            <div class="form-group <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">
                <label>Password</label>
                <input type="password" name="password" autocomplete="off" class="form-control">
                <span class="help-block"><?php echo $password_err; ?></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Login">
            </div>
            <p>Don't have an account? <a href="register.php">Sign up now</a>.</p>
        </form>
    </div>    
</body>
</html>
```

### Step 5: Creating the welcome module

Here's the code of our "welcome.php" file, where user is redirected after successful login.

```
<?php
/* Initialize the session */
session_start();
 
/* Check if the user is logged in, if not then redirect him to login page */
if(!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true){
    header("location: login.php");
    exit;
}
?>
 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Welcome</title>
    <link rel="stylesheet" href="assets/bootstrap.css">
    <style type="text/css">
        body{ font: 14px sans-serif; text-align: center; }
    </style>
</head>
<body>
    <div class="page-header">
        <h1>Hi, <b><?php echo htmlspecialchars($_SESSION["username"]); ?></b>. Welcome</h1>
    </div>
    <p>
        <a href="logout.php" class="btn btn-danger">Sign Out of Your Account</a>
    </p>
</body>
</html>
```

### Step 6: Creating the logout script

Now, let's create a "logout.php" file. When the user clicks on the log out or sign out link, the script inside this file destroys the session and redirect the user back to the login page.

```
<?php
/* Initialize the session */
session_start();
 
/* Unset all of the session variables */
$_SESSION = array();
 
/* Destroy the session */
session_destroy();
 
/* Redirect to login page */
header("location: login.php");
exit;
?>
```

## Sql Injection Execution Approach

SQL injections are one of the most common vulnerabilities found in web applications nowadays. 
I will explain what a SQL injection attack is and take a look at an example of a simple vulnerable PHP web 
application accessing a MySQL database. After that, we will look at several methods to prevent this attack, 
fixing the problem.

As we have already set up our php simple web application now we will try to attach on the developed web application.
Usually username and password is required to access dashboard (welcome.php) but we will enter following code in username text field and 
any password you can enter which will not validated while login.
```
' or 1 = 1 -- '
```
In backend php code will create sql query in the following way.
```
SELECT id, username, password FROM users WHERE username = '' or 1 = 1 -- '' and password = md5('123')
```
In where clause username field has null value but after that there is or condition which says 1 = 1 that is always true. 
After or condition there is (--) comment symbols which ignore the rest of the sql where clause. 

SQL Injection code may change as per the php writen code for sql query in single quotation or double quotation.

## Screenshots

### Registration
![Registration](https://raw.github.com/inforkgodara/sql-injection/master/screenshots/registration.png?raw=true "Registration")

### Login
![Login](https://raw.github.com/inforkgodara/sql-injection/master/screenshots/login.png?raw=true "Login")

### Sql where clause code in username field
![SQL code](https://raw.github.com/inforkgodara/sql-injection/master/screenshots/sql-where-clause-code-in-username-field.png?raw=true "SQL where clause code")

### Dashboard
![Dashboard](https://raw.github.com/inforkgodara/sql-injection/master/screenshots/dashboard.png?raw=true "Dashboard")

### MySQL Database Query
![MySQL Database Query](https://raw.github.com/inforkgodara/sql-injection/master/screenshots/mysql-database-query.png?raw=true "Database")

## How to avoid sql injection 

* Use prepared statements and parameterized queries
* Use PHP frameworks (Symfony, Laravel, Codeigniter, CakePhp and etc.) in which already used prepared statements.

## Detailed Video
* Video clip on demonstration: https://youtu.be/KH_4s2WVDK0
