#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>
 
int read (long,StringPtr,int);
int write (long,StringPtr,int);
 
int main(int argc, char **argv) {
 
	OSStatus myStatus;
	AuthorizationFlags myFlags = kAuthorizationFlagDefaults;              // 1
	AuthorizationRef myAuthorizationRef;                                  // 2
 
	myStatus = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment,  // 3
		myFlags, &myAuthorizationRef);
	if (myStatus != errAuthorizationSuccess)
		return myStatus;
 
	do {
		{
			AuthorizationItem myItems = {kAuthorizationRightExecute, 0,    // 4
				NULL, 0};
			AuthorizationRights myRights = {1, &myItems};                  // 5
 
			myFlags = kAuthorizationFlagDefaults |                         // 6
				kAuthorizationFlagInteractionAllowed |
				kAuthorizationFlagPreAuthorize |
				kAuthorizationFlagExtendRights;
			myStatus = AuthorizationCopyRights (myAuthorizationRef,       // 7
				&myRights, NULL, myFlags, NULL );
		}
 
		if (myStatus != errAuthorizationSuccess) break;
 
		{
			char myToolPath[] = "/usr/bin/id";
			char *myArguments[] = { "-un", NULL };
			FILE *myCommunicationsPipe = NULL;
			char myReadBuffer[128];
 
			myFlags = kAuthorizationFlagDefaults;                          // 8
			myStatus = AuthorizationExecuteWithPrivileges                  // 9
				(myAuthorizationRef, myToolPath, myFlags, myArguments,
				&myCommunicationsPipe);
 
			if (myStatus == errAuthorizationSuccess)
			for(;;) {
				int bytesRead = read (fileno (myCommunicationsPipe),
					myReadBuffer, sizeof (myReadBuffer));
				if (bytesRead < 1) break;
				write (fileno (stdout), myReadBuffer, bytesRead);
			}
		}
	} while (0);
 
	AuthorizationFree (myAuthorizationRef, kAuthorizationFlagDefaults);    // 10
 
	if (myStatus) printf("Status: %ld\n", myStatus);
	return myStatus;
}
