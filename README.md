CRON.RememberMe
==============================================

This package provides functionality for remembering users after login.

After logging in successfully a cookie will be set that contains a JWT,
which will be used to identify and log in the user during further visits.

This package does not provide the login form. Consider using [Flowpack.Neos.FrontendLogin](https://github.com/Flowpack/Flowpack.Neos.FrontendLogin),
configuring the loginFormFields and adding a remember-me checkbox to your login form.
