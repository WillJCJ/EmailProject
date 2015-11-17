# EmailProject
We have all received messages, specifically, emails supposedly from friends or contacts that are in fact spam either falsely sent in their name, or sent from their account after hacking into it. This project would involve designing and implementing a system that would prevent such messages being accepted by the recipient's messaging service, through use of automated digital signatures. The project will involve investigating digital signature systems and methods for verifying the user is present at a terminal when sending their message such as Bluetooth LE or biometrics and designing a coherent system to use such technologies to sign outgoing messages in a user-friendly way.

#Specification

##Basic

* Ability to digitally sign a message or document and verify the signature. Signed by client with their private key, then  sent to server where it is verified by their public key and discarded if it fails.

* Ability to generate keys. User can generate their key pair and send the public key to the server for storage.

* Create a server for holding public keys of users.

##Intermediate

* Combine the elements above into a basic messaging or email system. Combine the elements together so they all work as one system, with the client running one program to communicate with a server.

* Add smart user authentication to avoid having the user enter a complicated password for every message. Key file on the computer, or located on USB volume.

* Management (using a server) of user details, and secure checking of public keys. Server can store user information and keys. Server can verify that keys are correct.

##Advanced

* Explore more user friendly ways of verifying user is present at email generation (Bluetooth proximity unlock).

* Use a bluetooth LE app on user’s phone as a private key for signing messages automatically as long as phone is near computer Analyse/Secure the system against attacks. Employ various security measures to prevent different types of attacks.

* Make the messaging system more advanced, user friendly, secure and integrated. Make the system more polished and user-friendly.
