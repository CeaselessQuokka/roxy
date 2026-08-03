#!/bin/bash
DEPLOY_TO=~/Roxy
ENV_NAME=SiteEnv
SERVICE_NAME="roxy.service"
SITE_NAME="Roxy"
GITHUB_REPO_NAME="roxy"
SITE_CODE_ROOT="app"

if systemctl is-active --quiet "$SERVICE_NAME"; then
	echo "Stopping $SITE_NAME service."
	sudo systemctl stop "$SERVICE_NAME"
fi

echo "Removing previous build."
rm -rf "$DEPLOY_TO"
rm -rf ~/"$ENV_NAME"

echo "Retrieving newest build."
mkdir -p ~/Build
cd ~/Build
git clone --quiet "https://github.com/CeaselessQuokka/$GITHUB_REPO_NAME"

echo "Updating tooling."
# Keep the whole Tooling directory on the server. ~/Build is deleted at the end
# of this script, so without this the systemd and nginx configs are only ever
# reachable by pulling them from GitHub again -- exactly when you least want to
# be hunting for them.
rm -rf ~/Tooling
cp -r "$GITHUB_REPO_NAME"/Tooling ~/Tooling

mv ~/UpdateBuild.sh ~/UpdateBuildOld.sh
mv "$GITHUB_REPO_NAME"/Tooling/UpdateBuild.sh ~
# The failure-alert script also lives directly in the home directory: it has to
# survive the window where ~/Roxy has been torn down, and it is what emails you
# if the service will not come back up.
cp "$GITHUB_REPO_NAME"/Tooling/alert_on_failure.py ~
chmod +x ~/alert_on_failure.py

echo "Creating fresh environment."
cd ~
python3 -m venv "$ENV_NAME"
~/"$ENV_NAME"/bin/pip install --quiet -r ~/Build/"$GITHUB_REPO_NAME"/requirements.txt
cd ~/Build

echo "Deploying newest build."
sudo mv "$GITHUB_REPO_NAME"/"$SITE_CODE_ROOT" "$DEPLOY_TO"
rm -rf ~/Build

if systemctl list-unit-files "$SERVICE_NAME" | grep -q "$SERVICE_NAME"; then
	echo "Starting $SITE_NAME service."
	sudo systemctl start "$SERVICE_NAME"
	echo "Site successfully deployed."
else
	echo "Service $SERVICE_NAME not found. Create a systemd service to run the site."
fi
rm ~/UpdateBuildOld.sh
