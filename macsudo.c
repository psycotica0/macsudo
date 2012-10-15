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
	while(*string)
		if(*string++ == toCount)
			num++;
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
	output[k]='\0';

	return output;
}

void usage() {
	fputs("This command takes in another command and attempts to authorize it to run with super user permissions\n", stderr);
	fputs("Usage: MacSudo [-p CommandName] [-i IconPath] command\n", stderr);
	fputs("Where:\n", stderr);
	fputs(" -p Gives the name MacSudo should display is requesting permission\n", stderr);
	fputs(" -i Gives the a path to an icon to display\n", stderr);
}

/* 
This function is intended to be called just before the program exits.
It will print out more useful error message than just the status number.
*/
void outputError(int errorCode) {
	switch (errorCode) {
		case errAuthorizationSuccess:
			/* Do nothing, successful */
			break;
		case errAuthorizationDenied:
			fputs("Authorization Denied\n", stderr);
			break;
		case errAuthorizationCanceled:
			fputs("User Canceled Authorization\n", stderr);
			break;
		case errAuthorizationToolExecuteFailure:
		case errAuthorizationToolEnvironmentError:
			fputs("Error executing given command\n", stderr);
			break;
		default:
			fprintf(stderr, "Unexpected Error (%d)\n", errorCode);
	}
}

int main(int argc, char **argv) {
 
	OSStatus myStatus;
	AuthorizationFlags myFlags = kAuthorizationFlagDefaults;
	AuthorizationRef myAuthorizationRef;
	AuthorizationItem envItem[2];
	AuthorizationEnvironment env;	/*initialized later, stupid C90 rules*/

	/* This will hold the command to be executed as root */
	char * command;
	/* This will hold the flag for getopt */
	char getOptFlag;

	env.count=0;
	env.items=&(envItem[0]);

	while ((getOptFlag=getopt(argc,argv, "hp:i:")) != -1) {
		switch (getOptFlag) {
			case 'p':
				if (env.count >= 2) break;
				envItem[env.count].name = kAuthorizationEnvironmentPrompt;
				/* This function is not standard */
				/* Also, it's kind of a hack... */
				asprintf((char **)&envItem[env.count].value, "On behalf of %s, ", optarg);
				envItem[env.count].valueLength = (sizeof(char)*strlen((char*)envItem[env.count].value)) + 1;
				envItem[env.count].flags = 0;
				env.count++;
				break;
			case 'i':
				if (env.count >= 2) break;
				envItem[env.count].name = kAuthorizationEnvironmentIcon;
				envItem[env.count].value = strdup(optarg);
				envItem[env.count].valueLength = (sizeof(char)*strlen((char*)envItem[env.count].value)) + 1;
				envItem[env.count].flags = 0;
				env.count++;
				break;
			case 'h':
			default:
				usage();
				return EXIT_FAILURE;
		}
	}
 
	if (argc <= optind) {
		fputs("No command given.\n",stderr);
		return EXIT_FAILURE;
	}

	myStatus = AuthorizationCreate(NULL, &env, myFlags, &myAuthorizationRef);

	if (myStatus != errAuthorizationSuccess) {
		outputError(myStatus);
		return myStatus;
	}

	/* Put the command together */
	command=argvJoin(argv+optind);
 
	do {
		{
			AuthorizationItem myItems = {kAuthorizationRightExecute, 0, NULL, 0};
			AuthorizationRights myRights;

			myRights.count=1;
			myRights.items=&myItems;
 
			myFlags = kAuthorizationFlagDefaults |
				kAuthorizationFlagInteractionAllowed |
				kAuthorizationFlagPreAuthorize |
				kAuthorizationFlagExtendRights;
				myStatus = AuthorizationCopyRights (myAuthorizationRef, &myRights, &env, myFlags, NULL );
		}
 
		if (myStatus != errAuthorizationSuccess) break;
 
		{
			char myToolPath[] = "/bin/sh";
			char *myArguments[] = {"-c", NULL, NULL };
			FILE *myCommunicationsPipe = NULL;
			char myReadBuffer[128];

			myArguments[1]=command;
 
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

	outputError(myStatus);
	return myStatus;
}
