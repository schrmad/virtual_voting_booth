# CS483 Final Project: Virtual Election Booth

### PROJECT DESCRIPTION: 
This project develops secure election protocol for voting with two central facilities. It simulates an online voting system in which users input their social security number, receive a validation number, create an identification number, and submit a vote. Identification numbers along with their corresponding votes are displayed as the election's results.

### CONTRIBUTORS: 
Thanh Vu, Madeline Schroeder 
	(AES and RSA algorithms adapted from Practical Cryptography in Python)

### VERSION: 
12 March, 2022
### HOW PROJECT REQUIREMENTS ARE FULFILLED:
1. Only authorized voters can vote: We took in voter's social security number, and only people with valid SSN can vote
2. No one can vote more than once: each SSN can only be used to register once
3. No one can determine for whom anyone else voted: SSNs are encrypted and signed, and only anonymous ID numbers are shown in voting results
4. No one can duplicate anyone else's votes: everyone has a unique validation number that can only be used once
5. No one can change anyone else's vote without being discovered: each vote is encrypted, so if a vote is changed the original vote won't match the new vote
6. Every voter can make sure that his vote has been taken into account in the final tabulation: votes and ID numbers are displayed at the end
-------------------------------------------------------
### HOW-TO-RUN:
Everything needed to run this project is contained in the included Python file.
To run the simulation, compile and run the python file in an environment of your choice. After Clicking "run," you must type:
	
	main()

into the console, and press enter in order to begin the simulation.

### SIMULATION INSTRUCTIONS:
#### Phase 1: Voting registration
SAMPLE:
Without starting with 0, your 9-digit social security number: 123123123
Verify passed! (On failure, throw exception)
Backend: secure transfer successful!
Backend: secure transfer successful!
Thank you for submitting SSN. Your validation number:  4503143659

During this phase, the console will prompt the user to type a 9-digit social
security number (this is a simulation, don't enter your real social security
number!). This number cannot start with a 0. By default, the simulation registers
3 voters. To change this, you may change the number of voters being registered in
the call to registerVoter() in main() (on line 314). For example for 5 voters: 

	registerVoter(5, voter_ssn_list)
	
In the sample above, the social security number was successfully signed and encrypted, 
and the validation number was successfully encrypted. If a valid social security number 
is submitted (it cannot be one that was entered previously), then the program will print
a validation number. Sensitive data is encrypted, decrypted, and sometimes signed 
to simulate secure simulation. If encryption and decryption are successful (original 
and decrypted text match), then the text "Backend: secure transfer successful!"
will be printed twice. If they fail, then the message "Backend: 
secure transfer failed." will appear. Similarly, if a signature is successfully
verified, then the program print "Verify passed! (On failure, throw exception)"
An exception is thrown if a signature cannot be verified. 
	
#### Phase 2: Voting Session
SAMPLE:
The voting session begins now.
---------------------------------------------

Please input your validation number: 4503143659

After all voters have registered, the voting session will begin by displaying the
above sample. Like phase 1, the simulation handles 1 voter at a time. Copy and 
paste validation numbers printed in phase 1 in order to cast a vote. Submitting a 
validation number should print 1 "verify passed" message and one "secure transfer 
successful" message.

SAMPLE:
For ID number, input a 2-digit number from 10 to 99: 10

Next an identification number must be entered. These are used so that when the 
results are displayed, voters can easily verify that their vote was counted without
publically sharing their validation number. Like social security numbers, the program
will not accept repeat ID numbers. Submitting an identification number should print
1 "verify passed" message and one "secure transfer successful" message.

SAMPLE: 
[ID 10], please input 1 / 01 for nominee 1 or 2 / 02 for nominee 2: 01

Finally, a user casts their vote. Nominee 1 represents the Republican Party, and
nominee 2 represents the Democratic Party. After inputting their vote, this user
should see the following message: 

Verify passed! (On failure, throw exception)
Backend: secure transfer successful!
Thank you [ID 10] for casting vote

#### Phase 3: Results

SAMPLE:
Voting session over. We are pleased to announce that:
Democratic Party has won
ID: 10 | Vote: Republican Party
ID: 11 | Vote: Democratic Party
ID: 12 | Vote: Democratic Party

After all registered voters have voted, the results are displayed. This simulates
a user being able to check that their vote was counted.
	
Note: Requires cryptography library DL instructions: https://cryptography.io/en/latest/