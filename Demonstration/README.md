# Digital Signatures

This program is seperate from the website. This program contains more ways to help understand digital signatures. 

The instructions to run are on the README.md in the Digital_Signatures directory but additionally here for ease. <br>
One must ensure that all of the required packages are installed by using the following command:
<br> <i> Note: </i> the requirements.txt is back in the /Digital_Signatures directory
<p align="center">
   python3 -m pip install -r requirements.txt 
</p>

Once the packages are installed, navigate to the /Demonstration directory and run the following command:
<p align="center">
   python3 digital_signatures.py
</p>

List of commands for digital_signatures.py:  
 - --run 
 - --change_bit_size
 - --compare_bit_size
 - --compare_three_bit_sizes
 - --average_time
 - --multiple_averages
 - --help
 - --exit

What the commands do:
 - run : runs the program. Allows the user to input original data and then new data and checks whether the signatures are the same. The new data represents whether someone altered the original data in some sort of way. 
  - change_bit_size : allows the user to change the bit size.
  - compare_bit_size : allows a user to compare the time difference of verifying signatures of two different bit sizes.
  - compare_three_bit_size : allows a user to compare the time difference of verifying signatures of three different bit sizes.
  - --average_time : finds the average time to run based on a given number of trials.
  - --multiple_averages : finds the time of multiple averages; prints them to the screen and <i> can </i> be written to a workbook.
  - help : prints out all options.
  - exit : closes the program.
  </br>
All parameters for each command are found from user input after the command is chosen.
