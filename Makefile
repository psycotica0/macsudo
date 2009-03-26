.PHONY: clean

CFLAGS=-framework Security -I/Developer/SDKs/MacOSX10.4u.sdk/System/Library/Frameworks/Security.framework/Headers/ 

MacSudo: macsudo.c
	$(CC) $(CFLAGS) -o MacSudo macsudo.c

clean: 
	$(RM) MacSudo
