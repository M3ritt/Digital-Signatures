# Digital Signatures

<i> Note: </i> Since no database or endpoints were used for the website; the flask server cannot be deployed on a Linux device. Even using a display server such as Xming does not allow the flask server to be opened. The /Demonstration directory can be ran on a Linux device but server.py must be ran and opened on something other than a Linux device. 

<br>
This contains the code for a development server for a website as well as a small program that demonstrates how a digital signature works. The website is ran using Flask, hence why it is only a development server and not production. If desired to be ran on a production server, the Flask application can be run with Nginx using Gunicorn which would most likely be the most efficient way but did not feel it was necessary for this assignment.

If either the Flask Instance of the website or the demonstration program is desired to be ran, one must ensure that all of the required packages are installed by using the following command:<br>
<i> Note: </i> It is assumed Python is installed on the device entering the commands which the download can be found<a href="https://www.python.org/downloads/release/python-390/" target="_blank"> here</a>.
<p align="center">
   python3 -m pip install -r requirements.txt 
</p>

Once all of the packages are installed, navigate to the directory of which one is desired to be ran. If the server is desired to be ran to access the website, run the command:

<p align="center">
   python3 server.py
</p>

Then, the website can be accessed for personal use going through your local host, which is most likely: http://127.0.0.1:5000/ which cmd should tell you that the server is running and give the local host if the stated one is incorrect. 
<br> <br> <br>
If the website is not desired, then the /Demonstration can still be used as a souviner for the project and ran. The only difference to run that is one must navigate into the /Demonstration directory and run the following command:  

<p align="center">
   python3 digital_signatures.py
</p>

Note: <br>
All python code is commented to help ensure the readers understanding of how the process of digital signatures works.

The directories and outside files: 
   - /Demonstration is the python program that can be used to look at digital signatures without the website. Seperate from the website but usable.
   - /static contains all of the static files for the website to be styled correctly, including images, JavaScript and CSS files.  
   - /templates contains the html pages that are being used. 
   - requirements.txt is the file containing all the necessary packages.
   - server.py is the code for the Flask server.
   - signatures.py is the code used to generate the information about the digital signatures.
   
   
<b> Authors </b>
<ul> 
   <li> Josh Meritt  </li>
   <li> Eric Simonetti  </li>
   <li> Kira Garguilo  </li>
</ul>
