#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>
#include <stdlib.h>
#include <string.h>

/*
This function takes in an array of strings and joins them all into a single string.

It assumes the input char is argv-like, in that the last element in it is NULL
It allocates the space it needs.
This should be freed manually by the caller.
*/
char* argvJoin(char** input) {
	int requiredSize=0;
	char* output;
	int i;

	//Find the required size of the output
	for(i=0; input[i]!=NULL; i++) {
		//Add the size of the string plus 1 for the space we'll be using to join them.
		requiredSize += strlen(input[i]) + 1;
	}

	//Account for the null character
	requiredSize += 1;

	//Allocate the string
	output=malloc(sizeof(char) * requiredSize);
	if (output == NULL) {
		return NULL;
	}
	output[0]=NULL;

	//Now, fill in the values
	for(i=0; input[i]!=NULL; i++) {
		strcat(output, input[i]);
		strcat(output, " ");
	}

	return output;
}
 
int main(int argc, char **argv) {
 
	OSStatus myStatus;
	AuthorizationFlags myFlags = kAuthorizationFlagDefaults;
	AuthorizationRef myAuthorizationRef;
 
	if (argc <= 1) {
		fputs("No command given.\n",stderr);
		return EXIT_FAILURE;
	}

	myStatus = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, myFlags, &myAuthorizationRef);
	if (myStatus != errAuthorizationSuccess) return myStatus;
 
	do {
		{
			AuthorizationItem myItems = {kAuthorizationRightExecute, 0, NULL, 0};
			AuthorizationRights myRights = {1, &myItems};
 
			myFlags = kAuthorizationFlagDefaults |
				kAuthorizationFlagInteractionAllowed |
				kAuthorizationFlagPreAuthorize |
				kAuthorizationFlagExtendRights;
			myStatus = AuthorizationCopyRights (myAuthorizationRef, &myRights, NULL, myFlags, NULL );
		}
 
		if (myStatus != errAuthorizationSuccess) break;
 
		{
			char myToolPath[] = "/bin/sh";
			char *myArguments[] = {"-c", argv[1], NULL };
			FILE *myCommunicationsPipe = NULL;
			char myReadBuffer[128];
 
			myFlags = kAuthorizationFlagDefaults;
			myStatus = AuthorizationExecuteWithPrivileges(myAuthorizationRef, myToolPath, myFlags, myArguments, &myCommunicationsPipe);
 
			if (myStatus == errAuthorizationSuccess)
			for(;;) {
				int bytesRead = read (fileno (myCommunicationsPipe),
					myReadBuffer, sizeof (myReadBuffer));
				if (bytesRead < 1) break;
				write (fileno (stdout), myReadBuffer, bytesRead);
			}
		}
	} while (0);
 
	AuthorizationFree (myAuthorizationRef, kAuthorizationFlagDefaults);

	if (myStatus) printf("Status: %ld\n", myStatus);
	return myStatus;
}
