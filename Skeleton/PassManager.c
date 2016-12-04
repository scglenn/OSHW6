# include <stdio.h> 
# include <string.h>
# include <openssl/sha.h>
# include <openssl/hmac.h>
# include <openssl/evp.h>
# include <openssl/rand.h>
# include <assert.h> 
# include "util.h" 


//LLEntry * head ; 

char pFile[1024] ; 

void dump_to_password_file(char *fileName)
{
	//printf("DEBUG: password file %s\n",fileName); 
	FILE * fp = fopen(fileName, "w");
	if(!fp){
		printf("Error: Cannot open password file to write\n"); 
		exit(0); 
	}
	dump_datastructure_into_file(fp) ; 
	fclose(fp); 

}


void print_console_message()
{
	
	printf("\n\n\nSelect an integer from 1-5\n"); 
	printf("The integer option maps to the following commands:\n(1) register a user account\n(2) delete a user account\n(3) user login\n(4) change an account password\n(5) quit console\n\n\n");
}




/*IMPLEMENT THE FOLLOWING FUNCTIONS */

/*
DO NOT FORGET TO CHECK WHETHER THE USERNAME AND THE PASSWORD ARE VALID IN THE
BEGINNING OF EACH FUNCTION. THAT IS CHECK WHETHER THEY ONLY CONTAIN
CHARACTERS FROM THE CLASSES OF CHARACTERS ALLOWED. CONSULT THE PROJECT DESCRIPTION
TO FIND THE VALID CHARACTER CLASSES. 
*/


int register_user(unsigned char *user, unsigned char *password){
	printf("Registering user %s\n",user); 
        //write the body
        //Returns OKAY or ERROR
	

	// STEP 1: use the functions username_okay and password_okay to check whether the username and password respect the constraints 
	int nameResult =0;
	int passwordResult =0;
	nameResult = username_okay(user);
	if(nameResult != 1)
	{
		return ERROR;
	}
	passwordResult = password_okay(password);
	if(passwordResult !=1)
	{
		return ERROR;
	}
	// STEP 2: Use the find_user function to obtain a node to the linked list 
	// If the node returned by find_user is not null that means the user already exists
	// In which case print the error message "Error: User already exists\n" and return ERROR  
	if(find_user(user)!=NULL)
	{
		printf("Error: User already exists\n"); 
		return ERROR; 
	}
	//STEP 3: Generate a random salt of size SALT_SIZE using the getRandBytes function
	int getRandBytes(unsigned char * ptr, unsigned num_bytes)
	unsigned char* saltPointer = (unsigned char*) malloc(sizeof(unsigned char));
	int randSalt = getRandBytes(pointer,SALT_SIZE);
	if(randSalt!=1)//error occured
	{
		return ERROR;
	}
	//STEP 4: Generate the hashed password based on password and the salt
	unsigned char digest[SHA512_DIGEST_LENGTH]; 
	SHA512_CTX ctx;
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, password, strlen(password));
	assert(getRandBytes(saltPointer, SALT_SIZE) != -1 ) ; 
	SHA512_Update(&ctx, saltPointer, SALT_SIZE);
	SHA512_Final(digest, &ctx);

	char mdString[SHA512_DIGEST_LENGTH*2+1];
	for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
		sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
	//printf("SHA512 hash value: %s\n", mdString);
	//printf("LEN: %d\n",SHA512_DIGEST_LENGTH); 
	
	//STEP 5: Call the push_back function to add the user to the list 
	push_back(user, saltPointer, mdString);
	printf("DEBUG: Called register_user function\n");
	return OKAY ;
}



int delete_user(unsigned char *user, unsigned char * password){
        //write the body
        //Returns OKAY or ERROR

	// STEP 1: use the functions username_okay and password_okay to check whether the username and password respect the constraints 
	int nameResult =0;
	int passwordResult =0;
	nameResult = username_okay(user);
	if(nameResult != 1)
	{
		return ERROR;
	}
	passwordResult = password_okay(password);
	if(passwordResult !=1)
	{
		return ERROR;
	}
	// STEP 2: Use the find_user function to obtain a node to the linked list 
	// If the node returned by find_user is null that means the user does not exist
	// In which case print the error message "Error: User does not exist\n" and return ERROR  
	if(find_user(user)==NULL)
	{
		printf("Error: User does not exist\n"); 
		return ERROR; 
	}
	//STEP 3: Based on the stored salt and entered password calculate a hashed password and then check whether the calculated 
	//hashed password matches with the stored one
	//If the password does not match print the error message "Error: User password does not match\n" and return ERROR 

	//STEP 4: Then call the delete_node with the user name to delete the user entry 

        printf("DEBUG: Called delete_user function\n");
        return OKAY ;
}



int match_user(unsigned char *user, unsigned char * password){
        //write the body
        //Returns OKAY or ERROR

	// STEP 1: use the functions username_okay and password_okay to check whether the username and password respect the constraints 

	// STEP 2: Use the find_user function to obtain a node to the linked list 
	// If the node returned by find_user is null that means the user does not exist
	// In which case print the error message "Error: User does not exist\n" and return ERROR  

	//STEP 3: Based on the stored salt and entered password calculate a hashed password and then check whether the calculated 
	//hashed password matches with the stored one
	//If the password does not match print the error message "Error: User password does not match\n" and return ERROR 


        printf("DEBUG: Called login function\n");
        return OKAY ;
}

int change_user_password(unsigned char *user, unsigned char * password_current, unsigned char * password_new){
        //write the body
        //Returns OKAY or ERROR

	// STEP 1: use the functions username_okay and password_okay to check whether the username and password respect the constraints 

	// STEP 2: Use the find_user function to obtain a node to the linked list 
	// If the node returned by find_user is null that means the user does not exist
	// In which case print the error message "Error: User does not exist\n" and return ERROR  

	//STEP 3: Based on the stored salt and entered password calculate a hashed password and then check whether the calculated 
	//hashed password matches with the stored one
	//If the password does not match print the error message "Error: User password does not match\n" and return ERROR 

	// STEP 4: Create a new random salt for the new password and obtain the hashed password then call the update_user_password function to update 
	// the password entry for the function 

        printf("DEBUG: Called change_user_password function\n");
        return OKAY ;
}

/*IMPLEMENT THE ABOVE FUNCTIONS*/



void process_option(int option){
	switch(option){
		case 1:{
			printf("SELECTED OPERATION: <REGISTER USER ACCOUNT>\n");
			//registering a user account --- 
			printf("Enter username: ");
		    unsigned char username[1024];
		    scanf("%s",username) ;
		    printf("Enter password: ");
		    unsigned char password[1024] ;
		    scanf("%s",password) ;			
			if(register_user(username, password) == OKAY){
				printf("STATUS: Writing to password file\n"); 
				dump_to_password_file( pFile) ; 
				printf("STATUS: Finished writing to password file\n"); 
			}
			else{
				printf("Error: Cannot register user\n");
				
			}
			break ; 
		}
		
		case 2:{
			printf("SELECTED OPERATION: <DELETE USER ACCOUNT>\n");
			printf("Enter username to delete: ");
		    unsigned char username[1024];
		    scanf("%s",username) ;

		    printf("Enter password: ");
		    unsigned char password[1024];
		    scanf("%s",password) ;
			if(delete_user(username,password)==OKAY){
				printf("User deleted\n");
				printf("STATUS: Writing to password file\n"); 
				dump_to_password_file( pFile) ; 
				printf("STATUS: Finished writing to password file\n"); 

			}
			else{
				printf("Error: Cannot delete user\n"); 
			}

			break ; 
		} 

		case 3:{
			printf("SELECTED OPERATION: <USER LOGIN>\n");
			printf("Enter username: ");
		    unsigned char username[1024];
		    scanf("%s",username) ;
		    printf("Enter password: ");
		    unsigned char password[1024] ;
		    scanf("%s",password) ;
			if(match_user(username,password)==OKAY){
				printf("________________________\n");
				printf("|                       |\n");
				printf("| USER LOGIN SUCCESSFUL |\n");
				printf("|_______________________|\n");
			}
			else{ 
				printf("__________________________\n");
				printf("|                         |\n"); 
				printf("| USER LOGIN UNSUCCESSFUL |\n");
				printf("|_________________________|\n");
			}
			break ; 
		} 

		case 4: {
			printf("SELECTED OPERATION: <CHANGE PASSWORD>\n");
			printf("Enter username: ");
		    unsigned char username[1024];
		    scanf("%s",username) ;
		    printf("Enter current password: ");
		    unsigned char password[1024] ;
		    scanf("%s",password) ;
		    printf("Enter new password: ");
		    unsigned char npassword[1024] ;
		    scanf("%s",npassword) ;
			if(strcmp(password,npassword)==0){
				printf("Error: New and Old password are same\n");
				break ; 
			}
			if(change_user_password(username,password,npassword) == OKAY){
				printf("User password changed\n");
				printf("STATUS: Writing to password file\n"); 
				dump_to_password_file( pFile) ; 
				printf("STATUS: Finished writing to password file\n"); 
				
			}
			else printf("Error: Cannot change user password\n"); 
			break ; 
		}

		case 5: {
			printf("Error: Option 5 should not be handled here\n"); assert(0); break ; 
		}

		default: {
			printf("Error: Unknown option %d\n",option); assert(0); break ; 
		}

	}

}


int main(int argc, char *argv[]){

	if(argc != 2){
		printf("Error: Missing Arguments\n");
		printf("Usage: ./Executable-Name Password-File-Name\n"); 
		return 0 ; 
	}

	FILE * fp = fopen(argv[1], "r"); 
	if(!fp){
		printf("Error: Cannot open input file %s\n",argv[1]); 
		return 0 ; 
	}
	//load the password file in a data-structure 	
	parse_line_load_data_structure(fp) ; 
	fclose(fp) ; 

	strcpy(pFile, argv[1]); 

	while(1)
	{
		print_console_message(); 
		int option ; 
		printf("OPTION: "); 
		scanf("%d",&option);
		if(option==5)break; 
		process_option(option); 
	}
	dump_to_password_file( pFile) ;

	//clean up data structure; 
	delete_entire_list() ; 

	return 0 ; 
}

