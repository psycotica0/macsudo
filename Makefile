.PHONY: clean

CFLAGS=-framework Security -I/Developer/SDKs/MacOSX10.4u.sdk/System/Library/Frameworks/Security.framework/Headers/ 

macsudo: macsudo.c
	$(CC) $(CFLAGS) -o macsudo macsudo.c

clean: 
	$(RM) macsudo
