#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>
 
int main(int argc, char **argv) {
 
	OSStatus myStatus;
	AuthorizationFlags myFlags = kAuthorizationFlagDefaults;
	AuthorizationRef myAuthorizationRef;
 
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
			char myToolPath[] = "/usr/bin/id";
			char *myArguments[] = { "-un", NULL };
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
