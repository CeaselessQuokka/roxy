echo "Moving files..."
sudo mkdir /etc/roxy
sudo mv /etc/admin_credentials.txt /etc/roxy/admin_credentials.txt
sudo mv /etc/app_password.txt /etc/roxy/app_password.txt
sudo mv /etc/auth_tokens.txt /etc/roxy/auth_tokens.txt
echo "Files moved!"

echo "Setting permissions..."
sudo chown -R $USER:$USER /etc/roxy
sudo chmod 600 -R /etc/roxy
sudo chmod 700 /etc/roxy
echo "Permissions set; don't forget to create files.txt and misc.txt!"
