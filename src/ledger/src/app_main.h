/*******************************************************************************
*   (c) 2018 ZondaX GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
#pragma once

#include "JsonParser.h"

#define CLA 0x80
#define OFFSET_CLA       0
#define OFFSET_INS       1  //< Instruction offset
#define OFFSET_PCK_INDEX 2  //< Package index offset
#define OFFSET_PCK_COUNT 3  //< Package count offset
#define OFFSET_DATA      4  //< Data offset

extern parsed_json_t parsed_json;
extern char json_buffer[1000];

extern uint32_t json_buffer_write_pos;
extern uint32_t json_buffer_size;

extern volatile uint32_t stackStartAddress;

void app_init();

void app_main();