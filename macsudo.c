#include <Authorization.h>
#include <AuthorizationTags.h>

int main(int argc, char * argv[]) {
	OSStatus status;
	AuthorizationRef authRef;
	{
		AuthorizationItem items = {kAuthorizationRightExecute, 0, NULL, 0};
		AuthorizationRights auth={1, &items};
		AuthorizationFlags flags=
			kAuthorizationFlagDefaults 
			| kAuthorizationFlagInteractionAllowed  
			| kAuthorizationFlagExtendRights 
			;

		status=AuthorizationCreate(&auth, kAuthorizationEmptyEnvironment,flags, &authRef); 
		if (status != errAuthorizationSuccess) {
			fputs("Can't Create\n",stderr);
			return status;
		}
	}
	{
		FILE* pipe=NULL;
		char readBuffer[15];
		status = AuthorizationExecuteWithPrivileges(authRef,"/usr/bin/whoami", kAuthorizationFlagDefaults,NULL, &pipe);
		if (status == errAuthorizationSuccess){
			int bytesRead = read(fileno(pipe), readBuffer, sizeof(readBuffer));
			readBuffer[14]='\0';
			fputs(readBuffer,stdout);
		} else {
			fputs("No Auth\n",stderr);
			return status;
		}
	}
	AuthorizationFree(authRef, kAuthorizationFlagDefaults);
	return 0;
}
