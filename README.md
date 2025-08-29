# 🧑‍⚕️ Doctor Simple Web Application

**Doctor Simple Web Application** is a web app for **managing patients, profiles, doctors, and appointments**.  
It uses **React** for the frontend and **Node.js/Express** for the backend API with **MySQL database**, **JWT authentication**, and **Swagger API documentation**.  

The backend also includes **Winston logging**, **Helmet security headers**, **cookie parsing**, and **request sanitization** for better security.  

The app can be deployed on **Windows Server** with **NGINX reverse proxy**, **Let’s Encrypt SSL**, and **Cloudflare DNS**.  

---

## 🚀 Key Features

- 🔑 **Authentication & Authorization** – JWT token, user registration, login/logout  
- 👤 **Patient Profile** – View and update personal info, medical history  
- 👨‍⚕️ **Doctor Search** – Search by name or specialization  
- 📅 **Appointment Management** – Book and check doctor schedules  
- 📊 **Swagger Documentation** – Easy API testing and documentation  
- 🛡️ **Security** – Helmet, sanitizeRequest, rate limiter, cookie parser  
- 📜 **Server Logging** – Request and error logging with Winston  
- 🌐 **Deployment Ready** – Supports Windows Server + NGINX + HTTPS + Cloudflare  

---

## ⚙️ System Architecture

| Component                  | Description |
|----------------------------|-------------|
| **📱 React Frontend**       | SPA using React Components + CSS Modules |
| **🌐 Node.js Backend**      | RESTful API, JWT Auth, Swagger, Logging, Security Middleware |
| **💾 MySQL Database**       | Stores users, doctors, appointments, patient history |
| **🔧 Deployment Layer**     | Windows Server + NGINX Reverse Proxy + Let’s Encrypt SSL + Cloudflare DNS |

> Frontend and Backend are separate but communicate via REST APIs  

---

## 🧰 Tech Stack

### 💻 Frontend

- React + JavaScript  
- React Components + CSS Modules  
- Axios for API requests  
- React Router for navigation  
- Responsive design for desktop and mobile  

### 🌐 Backend (API)

- Node.js + Express  
- RESTful APIs: `/api/register`, `/api/login`, `/api/patient/*`, `/api/doctor/*`, `/api/appointment/*`  
- **Swagger** for API documentation  
- **Security Middleware**:
  - **Helmet** – Set secure HTTP headers  
  - **cookie-parser** – Parse and manage cookies  
  - **sanitizeRequest** – Prevent SQL/NoSQL injection and malicious payloads  
  - **express-rate-limit** – Protect against brute-force attacks  
- **Logging**: Winston for request and error logs  
- **MySQL Database**  
- **JWT & bcrypt** for authentication
  
### 🧰 Deployment & DevOps

- **Windows Server**  
- **NGINX Reverse Proxy**  
  - doctor.busitplus.com → React Frontend  
  - docapi.busitplus.com → Node.js API  
- **SSL / HTTPS** – Let’s Encrypt  
- **DNS** – Cloudflare  

### 🧪 Testing & Tools

- **Postman** – For testing all API endpoints efficiently.
- **Visual Studio Code** – Primary IDE for frontend and backend development.
- **MySQL Workbench** – For managing and querying the database.
- **Git & GitHub** – Version control and collaboration.
- **Swagger UI** – To explore and test RESTful APIs via interactive documentation.
- **Winston** – Logging server requests and errors.
- **cookie-parser** – For handling cookies in Express.js.
- **helmet** – Adds security headers to HTTP responses.
- **sanitizeRequest** – Sanitizes incoming requests to prevent injection attacks.

---

## 🛠️ Installation Guide

Follow these steps to set up the project locally or on your server.

### 1️⃣ Clone the Repositories

```bash
# Clone Frontend (React)
git clone https://github.com/teeprakorn1/doctor_react.git
cd doctor_react

# Clone Backend (Node.js API)
git clone https://github.com/teeprakorn1/doctor_nodejs.git
cd doctor_nodejs
```

### 2️⃣ Setup Backend (Node.js API)
#### Navigate to the backend folder:
```bash
cd doctor_nodejs
```
#### Install dependencies:
```bash
npm install
```
#### Create a .env file in the root of the backend:
```env
# Database Configuration
DATABASE_HOST=YOUR_DATA
DATABASE_USER=YOUR_DATA
DATABASE_PASS=YOUR_DATA
DATABASE_NAME=YOUR_DATA
DATABASE_PORT=3306

# Token Configuration
PRIVATE_TOKEN_KEY=YOUR_DATA_KEY
SWAGGER_TOKEN_KEY=YOUR_DATA_KEY

# Client URL
WEB_CLIENT_URL_DEV=http://localhost:3001
WEB_CLIENT_URL_PROD=https://YOUR_DATA.com
WEB_CLIENT_URL_PROD_2=https://www.YOUR_DATA.com
WEB_CLIENT_URL_PROD_3=https://doctor.YOUR_DATA.com
COOKIE_DOMAIN_PROD=.YOUR_DATA.com

COOKIE_DOMAIN_PROD=.YOUR_DATA.com

# Server Ports
SERVER_PORT=3000

# Server Configuration
# Environment Mode (0: Development, 1: Production)
ENV_MODE=0
```
#### Run database migrations / create tables manually in MySQL:
```sql
CREATE DATABASE doctor_db;
```
#### Start the backend server:
```bash
npm start
```
### 3️⃣ Setup Frontend (React)
#### Navigate to the frontend folder:
```bash
cd doctor_react
```
#### Install dependencies:
```bash
npm install
```
#### Create a .env file in the frontend root:
```env
#Server Configuration
REACT_APP_SERVER_PROTOCOL=YOUR_DATA
REACT_APP_SERVER_BASE_URL=YOUR_DATA
REACT_APP_SERVER_PORT=:YOUR_DATA

#Security Configuration
REACT_APP_SECREAT_KEY_CRYTO=YOUR_DATA_KEY

#API Configuration
REACT_APP_API_VERIFY=/api/verifyToken
REACT_APP_API_LOGIN_WEBSITE=/api/login
REACT_APP_API_LOGOUT_WEBSITE=/api/logout
REACT_APP_API_REGISTER_PATIENT=/api/register/patient
REACT_APP_API_GET_PROFILE_WEBSITE=/api/profile/get
REACT_APP_API_UPDATE_PROFILE_WEBSITE=/api/profile/patient/update

REACT_APP_API_GET_DOCTOR_NAME_WEBSITE=/api/doctor/name/get/
REACT_APP_API_GET_DOCTOR_SPECIALTY_WEBSITE=/api/doctor/specialty/get/
REACT_APP_API_DOCTOR_AVAILABILITY_WEBSITE=/api/doctor/availability

REACT_APP_API_DOCTOR=/api/doctor/
REACT_APP_API_AVAILABILITY=/availability
REACT_APP_API_APPOINTMENT_CREATE=/api/appointment/create
REACT_APP_API_APPOINTMENT_PATIENT=/api/patient/appointment
REACT_APP_API_APPOINTMENT_PENDING=/api/doctor/appointments/pending
REACT_APP_API_APPOINTMENT_ACTION=/api/doctor/appointments/action
REACT_APP_API_APPOINTMENT_SCHEDULE=/api/doctor/appointments/schedule
```
#### Start the frontend app:
```bash
npm start
```
React app will run on → http://localhost:3000
### 4️⃣ Access Swagger API Docs
#### Once the backend is running, open:
```bash
http://localhost:3001/api-docs
```
### 5️⃣ Deployment (Windows Server + NGINX + Cloudflare + SSL)
#### Build React for production
```bash
cd doctor_react
npm run build
```
#### Configure NGINX reverse proxy
Example configuration:
```nginx
server {
    server_name doctor.busitplus.com;

    root /var/www/doctor_react/build;
    index index.html;

    location / {
        try_files $uri /index.html;
    }
}

server {
    server_name docapi.busitplus.com;

    location / {
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```
#### Enable SSL with Let’s Encrypt
```bash
sudo certbot --nginx -d doctor.busitplus.com -d docapi.busitplus.com
```
#### Point DNS to server via Cloudflare
---
Done! Now you can access:
- Frontend → https://doctor.busitplus.com  
- Backend API → https://docapi.busitplus.com  
- API Docs (Swagger) → https://docapi.busitplus.com/api-docs
