#*******************************************************************************
#   Ledger App
#   (c) 2017 Ledger
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#*******************************************************************************

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.defines

#########
#  App  #
#########
APPNAME    = Radix
ifeq ($(TARGET_NAME), TARGET_NANOX)
ICONNAME   = nanox_icon.gif
else
ICONNAME   = nanos_icon.gif
endif

APPVERSION = 0.1.7

# The --path argument here restricts which BIP32 paths the app is allowed to derive.

# Radix BIP44 coin type will MAYBE be `536`, used in variable `APPPATH`,
# 536 = ASCII Dec value for r, a, d, i, x = 114+97+100+105+120 = 536.
# Please observe that `536` is NOT yet registred here: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
# Can be registered when this Ledger app is done.
BIP44_COIN_TYPE_RADIX= "44'/536'"


APP_LOAD_PARAMS = --path $(BIP44_COIN_TYPE_RADIX) --curve secp256k1 $(COMMON_LOAD_PARAMS)
APP_LOAD_FLAGS  = --appFlags 0x240
APP_SOURCE_PATH = src
SDK_SOURCE_PATH = lib_stusb lib_stusb_impl lib_u2f

ifeq ($(TARGET_NAME),TARGET_NANOX)
SDK_SOURCE_PATH  += lib_blewbxx lib_blewbxx_impl
SDK_SOURCE_PATH  += lib_ux
DEFINES          += HAVE_UX_FLOW
endif

APP_LOAD_PARAMS += $(APP_LOAD_FLAGS)

ifeq ($(CHAIN),)
CHAIN=Radix
endif

all: default

load: all
	python -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

delete:
	python -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

############
# Platform #
############

DEFINES += OS_IO_SEPROXYHAL IO_SEPROXYHAL_BUFFER_SIZE_B=256
DEFINES += HAVE_BAGL HAVE_SPRINTF HAVE_SNPRINTF_FORMAT_U

# Enabling debug PRINTF
DEBUG:=0
ifneq ($(DEBUG),0)
        ifeq ($(TARGET_NAME),TARGET_NANOX)
                DEFINES   += HAVE_PRINTF PRINTF=mcu_usb_printf
        else
                DEFINES   += HAVE_PRINTF PRINTF=screen_printf
        endif
else
        DEFINES   += PRINTF\(...\)=
endif

DEFINES += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=4 IO_HID_EP_LENGTH=64 HAVE_USB_APDU

DEFINES += APPVERSION=\"$(APPVERSION)\"

# U2F
DEFINES   += HAVE_U2F HAVE_IO_U2F
DEFINES   += U2F_PROXY_MAGIC=\"w0w\"
DEFINES   += USB_SEGMENT_SIZE=64
DEFINES   += BLE_SEGMENT_SIZE=32 #max MTU, min 20

#WEBUSB_URL = www.ledgerwallet.com
#DEFINES    += HAVE_WEBUSB WEBUSB_URL_SIZE_B=$(shell echo -n $(WEBUSB_URL) | wc -c) WEBUSB_URL=$(shell echo -n $(WEBUSB_URL) | sed -e "s/./\\\'\0\\\',/g")
DEFINES   += HAVE_WEBUSB WEBUSB_URL_SIZE_B=0 WEBUSB_URL=""

ifeq ($(TARGET_NAME),TARGET_NANOX)
DEFINES   += HAVE_BLE BLE_COMMAND_TIMEOUT_MS=2000
DEFINES   += HAVE_BLE_APDU # basic ledger apdu transport over BLE

DEFINES   += HAVE_GLO096 HAVE_UX_LEGACY
DEFINES   += HAVE_BAGL BAGL_WIDTH=128 BAGL_HEIGHT=64
DEFINES   += HAVE_BAGL_ELLIPSIS # long label truncation feature
DEFINES   += HAVE_BAGL_FONT_OPEN_SANS_REGULAR_11PX
DEFINES   += HAVE_BAGL_FONT_OPEN_SANS_EXTRABOLD_11PX
DEFINES   += HAVE_BAGL_FONT_OPEN_SANS_LIGHT_16PX
endif

##############
#  Compiler  #
##############

CC := $(CLANGPATH)clang
CFLAGS += -O3 -Os

AS := $(GCCPATH)arm-none-eabi-gcc
LD := $(GCCPATH)arm-none-eabi-gcc
LDFLAGS += -O3 -Os
LDLIBS += -lm -lgcc -lc

##################
#  Dependencies  #
##################

# import rules to compile glyphs
include $(BOLOS_SDK)/Makefile.glyphs
# import generic rules from the sdk
include $(BOLOS_SDK)/Makefile.rules

APP_SOURCE_PATH += src

dep/%.d: %.c Makefile

listvariants:
	@echo VARIANTS COIN Radix

