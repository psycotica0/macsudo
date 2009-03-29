#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
This function counts the number of times a certain character occurs in a string
*/
int charCount(char* string, char toCount) {
	int num=0;
	char *pos=string;
	while (1) {
		pos=strchr(pos+1, toCount);
		if (pos == NULL) {
			break;
		} else {
			num++;
		}
	}

	return num;
}

/*
This function takes in an array of strings and joins them all into a single string.

It's a little more specialized than that.
It wraps each entry in quotes, to protect the word boundries when being passed through as options as another command
It also has to therefore escape each " it finds.

It assumes the input char is argv-like, in that the last element in it is NULL
It allocates the space it needs.
This should be freed manually by the caller.
*/
char* argvJoin(char** input) {
	int requiredSize=0;
	char* output;
	int i,j,k;

	/* Find the required size of the output */
	for(i=0; input[i]!=NULL; i++) {
		/* Add the size of the string */
		requiredSize += strlen(input[i]);
		/* Add one for the space we'll be using to join them */
		requiredSize += 1;
		/* Add 2 for the quotes that will wrap each entry. */
		requiredSize += 2;
		/* Add 1 for every quote character that shows up (because they'll need to be escaped) */
		requiredSize += charCount(input[i],'"');
	}

	/* Account for the null character */
	requiredSize += 1;

	/* Allocate the string */
	output=malloc(sizeof(char) * requiredSize);
	if (output == NULL) {
		return NULL;
	}
	/* This variable should keep track of where in output we are */
	k=0;
	output[0]=NULL;

	/* Now, fill in the values */
	for(i=0; input[i]!=NULL; i++) {
		/* Put in the first quote */
		output[k]='"';
		k++;
		for(j=0; input[i][j]!=NULL; j++,k++) {
			if (input[i][j] == '"') {
				output[k]='\\';
				k++;
			}
			output[k]=input[i][j];
		}
		/* Put in the ending quote */
		output[k]='"';
		/* And space */
		output[k+1]=' ';
		k += 2;
	}

	return output;
}

void usage() {
	fputs("This command takes in another command and attempts to authorize it to run with super user permissions\n", stderr);
	fputs("Usage: MacSudo [-p CommandName] command\n", stderr);
	fputs("Where:\n", stderr);
	fputs(" -p Gives the name MacSudo should display is requesting permission\n", stderr);
}

int main(int argc, char **argv) {
 
	OSStatus myStatus;
	AuthorizationFlags myFlags = kAuthorizationFlagDefaults;
	AuthorizationRef myAuthorizationRef;
	AuthorizationItem envItem={kAuthorizationEnvironmentPrompt, 0, NULL, 0};
	AuthorizationEnvironment env={1, &envItem};

	/* This will hold the command to be executed as root */
	char * command;
	/* This will hold the flag for getopt */
	char getOptFlag;

	while ((getOptFlag=getopt(argc,argv, "hp:")) != -1) {
		switch (getOptFlag) {
			case 'p':
				/* This function is not standard */
				/* Also, it's kind of a hack... */
				asprintf((char **)&envItem.value, "On behalf of %s, ", optarg);
				envItem.valueLength = (sizeof(char)*strlen((char*)envItem.value)) + 1;
				break;
			case 'h':
			default:
				usage();
				if (envItem.value != NULL) {
					free(envItem.value);
				}
				return EXIT_FAILURE;
		}
	}
 
	if (argc <= optind) {
		fputs("No command given.\n",stderr);
		if (envItem.value != NULL) {
			free(envItem.value);
		}
		return EXIT_FAILURE;
	}

	if (envItem.value == NULL) {
		myStatus = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, myFlags, &myAuthorizationRef);
	} else {
		myStatus = AuthorizationCreate(NULL, &env, myFlags, &myAuthorizationRef);
	}

	if (myStatus != errAuthorizationSuccess) {
		if (envItem.value != NULL) {
			free(envItem.value);
		}
		return myStatus;
	}

	/* Put the command together */
	command=argvJoin(argv+optind);
 
	do {
		{
			AuthorizationItem myItems = {kAuthorizationRightExecute, 0, NULL, 0};
			AuthorizationRights myRights = {1, &myItems};
 
			myFlags = kAuthorizationFlagDefaults |
				kAuthorizationFlagInteractionAllowed |
				kAuthorizationFlagPreAuthorize |
				kAuthorizationFlagExtendRights;
			if (envItem.value == NULL) {
				myStatus = AuthorizationCopyRights (myAuthorizationRef, &myRights, NULL, myFlags, NULL );
			} else {
				myStatus = AuthorizationCopyRights (myAuthorizationRef, &myRights, &env, myFlags, NULL );
			}
		}
 
		if (myStatus != errAuthorizationSuccess) break;
 
		{
			char myToolPath[] = "/bin/sh";
			char *myArguments[] = {"-c", command, NULL };
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
	free(command);
	if (envItem.value != NULL) {
		free(envItem.value);
	}

	if (myStatus) printf("Status: %ld\n", myStatus);
	return myStatus;
}
