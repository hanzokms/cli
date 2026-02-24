#!/bin/bash

PLATFORM=
ARCH=
TEMP_DOWNLOAD_FOLDER=

function delete_temp_install_folder()
{
  $(rm -rf $TEMP_DOWNLOAD_FOLDER 2> /dev/null)
}

# platform
case "$(uname -s)" in
 Linux) PLATFORM='linux';;
 Darwin) PLATFORM='darwin';;
 CYGWIN*|MINGW*|MSYS*) PLATFORM='windows';;
 FreeBSD) PLATFORM='freebsd';;
 *)
   echo "Your platform doesn't seem to be of type darwin, linux or windows"
   echo "Your architecture is $(uname -m) and your platform is $(uname -s)"
   exit 1
   ;;
esac

# architecture
if [[ "$(uname -m)" == 'x86_64' || "$(uname -m)" == "amd64" ]]; then
  ARCH="amd64"
elif [[ "$(uname -m)" == armv5* ]]; then
  ARCH="armv5"
elif [[ "$(uname -m)" == armv6* ]]; then
  ARCH="armv6"
elif [[ "$(uname -m)" == armv7* ]]; then
  ARCH="armv7"
elif [[ "$(uname -m)" == 'arm64' || "$(uname -m)" == 'aarch64' ]]; then
  ARCH="arm64"
elif [[ "$(uname -m)" == "i386" || "$(uname -m)" == "i686" ]]; then
  ARCH="i386"
else
  echo >&2 "Your architecture doesn't seem to supported. Your architecture is $(uname -m) and your platform is $(uname -s)"
  exit 1
fi

# Credit https://stackoverflow.com/questions/20010199/how-to-determine-if-a-process-runs-inside-lxc-docker
if [[ "$(cat /proc/1/cgroup 2> /dev/null | grep docker | wc -l)" > 0 ]] || [ -f /.dockerenv ]; then
  IS_RUNNING_IN_DOCKER=true
else
  IS_RUNNING_IN_DOCKER=false
fi

# example: v0.0.98
LATEST_RELEASE_VERSION=$(curl -s "https://api.github.com/repos/hanzokms/cli/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

# example: 0.0.98
NUMERIC_RELEASE_VERSION="${LATEST_RELEASE_VERSION:1}"

DOWNLOAD_LINK="https://github.com/hanzokms/cli/releases/download/${LATEST_RELEASE_VERSION}/cli_${NUMERIC_RELEASE_VERSION}_${PLATFORM}_${ARCH}.tar.gz"

CHECK_IF_BINARY_EXISTS=$(curl -s -o -L /dev/null -w "%{http_code}" ${DOWNLOAD_LINK})
if [[ $CHECK_IF_BINARY_EXISTS == "000Not Found404" ]]; then
  echo "Looks like we do not yet have a binary for this architecture and platform."
  echo "Your architecture is $(uname -m) and your platform is $(uname -s)"
  exit 1
fi

# make temp install folder
mkdir -p kms_temp_download_folder

cd kms_temp_download_folder

TEMP_DOWNLOAD_FOLDER=$(pwd)

# download latest cli
curl -L -o kms-binary.tar.gz ${DOWNLOAD_LINK}

# open up the tar file
tar zxf kms-binary.tar.gz

if [ "$PLATFORM" == "darwin" ] || [ $RUNNING_IN_DOCKER ] ; then
  if [[ -d /usr/local/bin ]]; then
    mv kms /usr/local/bin/
    echo "Hanzo KMS CLI ${LATEST_RELEASE_VERSION} has been installed in /usr/local/bin."
  else
    echo >&2 "Error: /usr/local/bin does not exist. You must create it before reinstalling"
    delete_temp_install_folder
    exit 1
  fi
elif [ "$PLATFORM" == "windows" ]; then
  mkdir $HOME/bin 2> /dev/null
  mv kms.exe $HOME/bin/
  echo "Hanzo KMS CLI ${LATEST_RELEASE_VERSION} has been installed in $HOME/bin"
  echo "Please add $HOME/bin to your system PATH"
else
  sudo mv kms /usr/local/bin/
  echo "Hanzo KMS CLI ${LATEST_RELEASE_VERSION} has been installed in /usr/local/bin."
fi

delete_temp_install_folder
