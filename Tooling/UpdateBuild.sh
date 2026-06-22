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
mv ~/UpdateBuild.sh ~/UpdateBuildOld.sh
mv "$GITHUB_REPO_NAME"/Tooling/UpdateBuild.sh ~

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
