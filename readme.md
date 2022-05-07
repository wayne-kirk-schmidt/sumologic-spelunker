Sumo Logic Data Doctor
======================

Sumo Logic Spelunker allows clients to compare existing data platforms to Sumo Logic.
For Spelunker, it uses a Splunk diag file and publishes this to Sumo Logic.

Want to find out how your Splunk deployment would look in Sumo Logic? Time to go spelunking!

Business Case
=============

Curious what was the business goals we wanted to solve? 

Please read on in our [writeup](doc/writeup.md)!

Installing the Scripts
=======================

Each script is command line based. They can be used by themselves or as part of other software.
Thus, the utilities can be easily merged into a DevOPs tool such as Chef or Ansible or Terraform.

All scripts are python3. The complete list of modules are provided to aid installation.
You will need to use Python 3.6 or higher and the modules listed in the dependency section.  

The steps are as follows: 

    1. Download and install python 3.6 or higher from python.org. Append python3 to the LIB and PATH env.

    2. Download and install git for your platform if you don't already have it installed.
       It can be downloaded from https://git-scm.com/downloads
    
    3. Open a new shell/command prompt. It must be new since only a new shell will include the new python 
       path that was created in step 1. Cd to the folder where you want to install the scripts.
    
    4. Execute the following command to install pipenv, which will manage all of the library dependencies:
    
        sudo -H pip3 install pipenv 
 
    5. Clone this repository. This will create a new folder

    6. Change into the folder. Type the following to install all the package dependencies 
       (this may take a while as this will download all of the libraries used):

        pipenv install
        
Dependencies
============

See the contents of "pipfile"

Script Names and Purposes
=========================

The installation is organized into sub directories:

    1. ./bin - all of the vendor scripts for installation

*  ./bin/sumologic_spelunker.py - analysis for Splunk Systems in Sumo Logic

    2. ./lib - has samples queries to use for analysis
    3. ./etc - has an example of a config file to set ENV variables for access

To Do List:
===========

* Build an Ansible wrapper for the scripts

* Add depdndency checking for pip modules

License
=======

Copyright 2019 Wayne Kirk Schmidt
https://www.linkedin.com/in/waynekirkschmidt

Licensed under the Apache 2.0 License (the "License");

You may not use this file except in compliance with the License.
You may obtain a copy of the License at

    license-name   APACHE 2.0
    license-url    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Support
=======

Feel free to e-mail me with issues to: 

*    wschmidt@sumologic.com

*    wayne.kirk.schmidt@gmail.com

I will provide "best effort" fixes and extend the scripts.

