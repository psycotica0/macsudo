#include <Authorization.h>
#include <AuthorizationTags.h>

int main(int argc, char * argv[]) {
	OSStatus status;
	AuthorizationRef authRef;
	{
		char prompt[] = "On behalf of MarketForce,";
		AuthorizationItem items = {kAuthorizationRightExecute, 0, NULL, 0};
		AuthorizationRights auth={1, &items};
		AuthorizationFlags flags=
			kAuthorizationFlagDefaults 
			| kAuthorizationFlagInteractionAllowed  
			| kAuthorizationFlagExtendRights 
			;
		AuthorizationItem envItems = {kAuthorizationEnvironmentPrompt, sizeof(prompt), prompt, 0};
		AuthorizationEnvironment env = {1, &envItems};

		status=AuthorizationCreate(&auth, &env,flags, &authRef); 
		if (status == errAuthorizationCanceled) {
			fputs("Auth Canceled\n",stderr);
			return status;
		} else if (status == errAuthorizationDenied) {
			fputs("Auth Denied\n",stderr);
			return status;
		} else if (status != errAuthorizationSuccess) {
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
		} else if (status == errAuthorizationToolExecuteFailure 
				|| status == errAuthorizationToolEnvironmentError) {
			fputs("Execution Failed\n", stderr);
			return status;
		} else {
			fputs("No Auth\n",stderr);
			return status;
		}
	}
	AuthorizationFree(authRef, kAuthorizationFlagDefaults);
	return 0;
}
