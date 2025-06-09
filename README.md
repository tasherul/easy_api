# Easy API 🚀

A single PHP file to automatically generate a RESTful API with JWT authentication for your functions. Just define your functions, and Easy API handles the rest!

![Demo](https://raw.githubusercontent.com/tasherul/easy_api/refs/heads/main/demo.webp) *https://easy-api.apitsoft.com/docs*


![Demo](https://raw.githubusercontent.com/tasherul/easy_api/refs/heads/main/essy_api.png) 

## Features ✨
- 🛡️ **JWT Authentication** - Secure your API endpoints automatically
- 🔌 **Zero Configuration** - Just add your functions and it works
- 📦 **Single File** - Entire solution in one `index.php` file
- 🔍 **Auto-Documentation** - Built-in API documentation
- 🚦 **Debug Mode** - Toggle debugging with `.env` setting
- � **Lightweight** - No heavy frameworks or dependencies

### ⛁ If you want to add a `mysql` easy coding then check on [`tasherul/easy_db`](https://github.com/tasherul/easy_db).

## Installation ⚡

### 1. Clone the Repository
```bash
git clone https://github.com/tasherul/easy_api.git
```

### 2. Web Server Configuration
Apache
If you're using Apache, create a .htaccess file with the following content:
```bash
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteRule ^(.*)$ index.php [QSA,L]
```
Nginx
If you're using Nginx, add the following to your site configuration:
```bash
location / {
  if (!-e $request_filename){
    rewrite ^(.*)$ /index.php break;
  }
}
```

### 3. Create a .env File
Add a .env file in the root directory with the following contents:
```bash
JWT_SECRET=super_secure_key
DEBUG=true
```

### Usage
Define your PHP functions anywhere in the same file or included files.
Annotate them with @route and optionally @auth to control access.
Easy API will automatically generate endpoints based on your definitions.
```bash
* @route POST /hello
* @desc Login and receive JWT token
* @tag Public
* @body {"username":"admin","password":"password"}
* @response 200 {"message":"Hello, world!"}
function sayHello() {
    return App::respond(['message' => 'Hello, world!']);
}
```
Visit `/docs` to interact with the auto-generated API documentation.

### Authentication 🔐
Easy API uses JWT for security. Include this in your requests:
```bash
jwtauth: YOUR_JWT_TOKEN
```

Contribution
Pull requests are welcome! Please open an issue to discuss any major changes first.
Made with ❤️ by @tasherul

### License 📄
MIT License - See LICENSE for more information.

### Key Highlights:
1. **Visual Appeal**: Used emojis and clear sections for better readability
2. **Complete Documentation**: Covers all aspects from installation to usage
3. **Code Formatting**: Proper Markdown code blocks for commands and configurations
4. **Security Emphasis**: Clearly explains JWT authentication process
5. **Quick Start**: Developers can get started immediately with the example

You can copy this directly into your `README.md` file. For even better presentation:
- Add actual screenshots/GIFs of your API in action
- Include a real demo link if available
- Add a "Troubleshooting" section if common issues are known
- Consider adding a "Roadmap" section for future features

