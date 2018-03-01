/**********************************************************************

   File          : cmpsc497-main.c
   Description   : Server project shell

   By            : Trent Jaeger

***********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include "cmpsc497-kvs.h"
#include "cmpsc497-ssl.h"
#include "cmpsc497-format-6.h"   // student-specific

/* Defines */
#define NAME_LEN    16
#define SALT_LEN    16
#define HASH_LEN    32
#define PWD_LEN     (HASH_LEN-SALT_LEN)
#define OBJ_LEN     188 // see what marshall says  // size of object tree for this project
#define KEY_LEN     8
#define PADDING     "----"
#define PAD_LEN     4
#define LINE_SIZE   100

//My added definitions
#define NUM_FIELDS_A 7
#define NUM_FIELDS_B 3
#define NUM_FIELDS_C 5
#define NUM_FIELDS_D 5


#define PASSWDS_PATH "./passwds-file"
#define OBJECTS_PATH "./objects-file"

struct kvs *Passwds;
struct kvs *Objects;


/* Project APIs */
// public 
extern int set_password( char *username, char *password );
extern int set_object( char *filename, char *username, char *password );
extern int get_object( char *username, char *password, char *id );

// internal
extern int unknown_user( char *username );
extern int authenticate_user( char *username, char *password );
extern struct A *upload_A( FILE *fp );
extern struct B *upload_B( FILE *fp );
extern struct C *upload_C( FILE *fp );
extern struct D *upload_D( FILE *fp );
extern struct E *upload_E( FILE *fp );
extern struct F *upload_F( FILE *fp );
extern unsigned char *marshall( struct A *objA );
extern struct A *unmarshall( unsigned char *obj );
extern int output_obj( struct A *objA, char *id );
extern int kvs_dump( struct kvs *kvs, char *filepath );

/*****************************

Invoke:
cmpsc497-p1 set user-name password obj-file
cmpsc497-p1 get user-name password obj-id

Commands:
<set_password> user-name password 
<set_object> user-name password obj-file
<get_object> user-name password obj-id

1 - set password - user name and password
    compute random salt and hash the salt+password

2 - set object - authenticate user for command
    and enter object into object store 

3 - get-object - authenticate user for command
    and retrieve object from object store by id

Object store - array of objects - base object reference and password hash

Need to dump objects and password hashes to file(s)

******************************/

/**********************************************************************

    Function    : main
    Description : Set object or get object in Objects KVS.
                  If password is not already created, an entry
                  is created in the Passwds KVS linking the 
                  username and password for future operations.
    Inputs      : argc - cmpsc497-p1 <op> <username> <password> <file_or_id>
                  argv - <op> may be "set" or "get"
                       - last arg is a filename on "set" (for object input)
                         and an object id on "get" to retrieve object
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int main( int argc, char *argv[] )
{
	int rtn;
	assert( argc == 5 );

	crypto_init();  // Necessary for hashing?
	ENGINE *eng = engine_init();

	/* initialize KVS from file */
	Passwds = (struct kvs *)malloc(sizeof(struct kvs));
	Objects = (struct kvs *)malloc(sizeof(struct kvs));
	kvs_init( Passwds, PASSWDS_PATH, NAME_LEN, HASH_LEN, HASH_LEN, PAD_LEN );// Maybe change Hash_Len to Salt_Len
	kvs_init( Objects, OBJECTS_PATH, KEY_LEN, OBJ_LEN, NAME_LEN, PAD_LEN );  // OBJ_LEN - size of the object tree for this project

	if ( strncmp( argv[1], "set", 3 ) == 0 ) {
		if ( unknown_user( argv[2] )) {
			rtn = set_password( argv[2], argv[3] );
			assert( rtn == 0 );
		}
		rtn = set_object( argv[4], argv[2], argv[3] );
	}
	else if ( strncmp( argv[1], "get", 3 ) == 0 ) {
		rtn = get_object( argv[2], argv[3], argv[4] );
	}
	else {
		printf( "Unknown command: %s\nExiting...\n", argv[1] );
		exit(-1);
	}

	kvs_dump( Passwds, PASSWDS_PATH ); 
	kvs_dump( Objects, OBJECTS_PATH ); 

	crypto_cleanup();
	engine_cleanup( eng );
  
	exit(0);
}

/**********************************************************************

    Function    : set_password
    Description : Generate salt and compute password hash
                  Store username (key), password hash (value), and salt (tag) in Passwds KVS
    Inputs      : username - username string from user input
                  password - password string from user input
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int set_password( char *username, char *password )
{ 
	int rtn;//Return value
	unsigned char salt[SALT_LEN];//Random 16 byte salt
	int digest_len;//Length of digest hash

	rtn = RAND_bytes((unsigned char *)salt, SALT_LEN);//Get random salt
	unsigned char *name = (unsigned char *)malloc(NAME_LEN);

	assert( strlen( username ) <= NAME_LEN );

	memset( name, 0, NAME_LEN );
	memcpy( name, username, strlen(username) );

	unsigned char *hash = (unsigned char *)malloc(HASH_LEN);//Allocate hash memory
	unsigned char *digest = (unsigned char *)malloc(HASH_LEN);//Allocate digest memory
	memset(hash, 0, HASH_LEN);//Set hash memory to NULL
	memset(digest, 0, HASH_LEN);//Set digest memory to NULL

	assert( strlen( password ) <= PWD_LEN );//Check if password is valid

	memcpy(hash, salt, SALT_LEN);
	memcpy(&hash[SALT_LEN], password, strlen(password));
	digest_message(hash, HASH_LEN, &digest, &digest_len);//Get hash value (digest)
	
	kvs_auth_set( Passwds, name, digest, &salt);//Set password and store hash
	if(rtn == 0)
	{
		rtn = -1;//Failure
	}
	else if(rtn == 1)
	{
		rtn = 0;//Success
	}

	free(hash);
	hash = NULL;
	free(digest);
	digest = NULL;
	free(name);
	name = NULL;
	return rtn;
}


/**********************************************************************

    Function    : unknown_user
    Description : Check if username corresponds to entry in Passwds KVS
    Inputs      : username - username string from user input
    Outputs     : non-zero if true, NULL (0) if false

***********************************************************************/

int unknown_user( char *username )
{
	unsigned char hash[HASH_LEN];
	unsigned char salt[SALT_LEN];
	unsigned char *name = (unsigned char *)malloc(NAME_LEN);

	assert( strlen( username ) <= NAME_LEN );

	memset( name, 0, NAME_LEN );
	memcpy( name, username, strlen(username) );

	return( kvs_auth_get( Passwds, name, &hash, &salt ));
}


/**********************************************************************

    Function    : authenticate_user
    Description : Lookup username entry in Passwds KVS
                  Compute password hash with input password using stored salt
                  Must be same as stored password hash for user to authenticate
    Inputs      : username - username string from user input
                  password - password string from user input
    Outputs     : non-zero if authenticated, 0 otherwise

***********************************************************************/

int authenticate_user( char *username, char *password )
{
	unsigned char *storedHash;//Hash already stored for user
	unsigned char *salt;//salt already stored for user
	int digest_len;
	int rtn = 0;
	unsigned char *name = (unsigned char *)malloc(NAME_LEN);

	assert( strlen( username ) <= NAME_LEN );

	memset( name, 0, NAME_LEN );
	memcpy( name, username, strlen(username) );
	kvs_auth_get( Passwds, name, &storedHash, &salt);
	
	//Allocate memory for hash with current input password
	unsigned char *inputHash = (unsigned char *)malloc(HASH_LEN);
	unsigned char *digest = (unsigned char *)malloc(HASH_LEN);//Allocate memory for current digest
	memset(inputHash, 0, HASH_LEN);//Set inputHash memory to NULL
	memset(digest, 0, HASH_LEN);//Set digest memory to NULL
	
	assert( strlen( password ) <= PWD_LEN );//Check if password is valid
	memcpy(inputHash, salt, SALT_LEN);
	memcpy(&inputHash[SALT_LEN], password, strlen(password));
	digest_message(inputHash, HASH_LEN, &digest, &digest_len);//Get hash value (digest)
	
	//Compare current hash with stored hash for user
	if(memcmp(digest, storedHash, digest_len) == 0)
	{
		rtn = 1; //Authenticated!!
	}
	else
	{
		rtn = 0;//Not authenticated
	}

	free(inputHash);
	inputHash = NULL;
	free(digest);
	digest = NULL;
	free(name);
	name = NULL;

	return rtn;
}


/**********************************************************************

    Function    : set_object
    Description : Authenticate user with username and password
                  If authenticated, read input from filename file
                  Upload each structure by calling upload_X for struct X
    Inputs      : filename - containing object data to upload
                  username - username string from user input
                  password - password string from user input
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int set_object( char *filename, char *username, char *password )
{
	//Check if user is authenticated
	if ( !authenticate_user( username, password )) {
		fprintf(stderr, "Authenticate_user was unsuccessful\n");
		return -1;//Not authenticated
	}
	unsigned char *token = (unsigned char *)malloc(LINE_SIZE);
	memset(token, 0, LINE_SIZE);
	unsigned char *name2 = (unsigned char *)malloc(LINE_SIZE);
	memset(name2, 0, LINE_SIZE);
	unsigned char *value = (unsigned char *)malloc(LINE_SIZE);
	memset(value, 0, LINE_SIZE);
	unsigned char *extra;
	long offset = 0;//File offset
	unsigned char *buff = (unsigned char *)malloc(LINE_SIZE);
	memset(buff, 0, LINE_SIZE);
	unsigned char *key = (unsigned char *)malloc(KEY_LEN);//Current token in line
	memset( key, 0, KEY_LEN);
	unsigned char *name = (unsigned char *)malloc(NAME_LEN);
	size_t len = LINE_SIZE;
	char *num;
	long id;

	assert( strlen( username ) <= NAME_LEN );

	memset( name, 0, NAME_LEN );
	memcpy( name, username, strlen(username) );
	unsigned char *flag;//Used to check when the last token in line has been reached
	int rtn;//Return value
	FILE *fp = fopen(filename, "r");//Open file
	assert(fp != NULL);
	assert(getline(&buff, &len, fp) != -1);

	while(strncmp(buff, "\n", strlen(buff)) == 0)//If line is empty
	{
		offset = ftell(fp);
		assert(offset != -1L);
		assert(getline(&buff, &len, fp) != -1);
	}
	assert(sscanf(buff, "%s %s %s", token, name2, value) == 3);
	if(strncmp(token, "struct", strlen(token)) != 0)// If first token is not "struct" then error
	{
		fprintf(stderr, "Error: First token in file is not struct\n");
		return -1;
	}
	
	if(value[strlen(value) - 1] == '\n')
	{
		value[strlen(value) - 1] = '\0';//Replace '\n' at end with '\0'
	}
	id = strtol(value, &num, 10);
	assert(ERANGE != errno && num != value && ('\n' == *num || '\0' == *num));
								
	
	memcpy( key, value, strlen(value));
	struct A *objA = upload_A(fp);

	if(objA != NULL)//If upload A was successful
	{
		unsigned char *obj = marshall(objA);//Marshall objA
		kvs_auth_set(Objects, key, obj, name);//Set the object KVS
		rtn = 0;//Successful
	}
	else//If upload A was unsuccessful
	{
		fprintf(stderr, "Upload_A was unsuccessful\n");
		rtn = -1;//Failure
	}
		
	assert(fclose(fp) == 0);//Close file

	free(value);
	value = NULL;
	free(name2);
	name2 = NULL;
	free(token);
	token = NULL;
	free(buff);
	buff = NULL;
	free(key);
	key = NULL;
	free(name);
	name = NULL;
	return rtn;
}


/**********************************************************************

    Function    : get_object
    Description : Authenticate user with username and password
                  If authenticated, retrieve object with id from Objects KVS
                  Unmarshall the object into structured data 
                  and output all string and int fields from structs A, B, and last
    Inputs      : username - username string from user input
                  password - password string from user input
                  id - identifier for object to retrieve
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int get_object( char *username, char *password, char *id )
{
	unsigned char *key = (unsigned char *)malloc(KEY_LEN);
	unsigned char *name, *obj;
	int rc;

	struct A *objA;

	if ( !authenticate_user( username, password )) {
		fprintf(stderr, "get_object authentication failed %s:%s\n", username, password );
		return -1;
	}

	assert( strlen(id) <= KEY_LEN);
	assert( strlen(username) <= NAME_LEN);

	memset( key, 0, KEY_LEN );
	memcpy( key, id, strlen(id) );

	rc = kvs_auth_get( Objects, key, &obj, &name );
 
	if ( rc == 0 ) {  // found object
		// verify name == owner
		if ( strncmp( (char *)name, username, strlen( username )) != 0 ) {
			fprintf(stderr, "get_object failed because user is not owner: %s:%s\n", 
				username, name );
			return -1;
		}

		// output object
		objA = unmarshall( obj );
		output_obj( objA, id );
	}
	else {
		fprintf(stderr, "get_object failed to return object for key: %s\n", id );
		return -1;
	}

	return 0;
}


/**********************************************************************

    Function    : upload_A 
    Description : For each line in file referenced by fp 
                  Assign value to struct field for object A (ints and strings)
                  or call upload_X function to upload data for struct X
    Inputs      : fp - file pointer for object input file
    Outputs     : objA - pointer to struct A or NULL

***********************************************************************/

struct A *upload_A( FILE *fp )
{
	struct A* objA = (struct A*)malloc(sizeof(struct A));
	memset(objA, 0, sizeof(struct A));
	unsigned char *buff = (unsigned char *)malloc(LINE_SIZE);
	memset(buff, 0, LINE_SIZE);
	unsigned char *token = (unsigned char *)malloc(LINE_SIZE);
	memset(token, 0, LINE_SIZE);
	unsigned char *name = (unsigned char *)malloc(LINE_SIZE);
	memset(name, 0, LINE_SIZE);
	unsigned char *value = (unsigned char *)malloc(LINE_SIZE);
	memset(value, 0, LINE_SIZE);
	unsigned char *extra = NULL;//To test if there are too many tokens on the line
	long offset = 0;//File offset
	int rtn = 0;//Return flag
	int flagA = 0;
	int countA = 0;//To count if all struct members have been filled
	int structFlag = 0;
	int i;
	size_t len = LINE_SIZE;
	char *num;
	ssize_t read;


	assert(fseek(fp, 0L, SEEK_SET) == 0);//Go to beginning of file
	assert(getline(&buff, &len, fp) != -1);
	
	while(strncmp(buff, "\n", strlen(buff)) == 0)//While line is empty
	{
		offset = ftell(fp);//Save file offset
		assert(offset != -1L);
		assert(getline(&buff, &len, fp) != -1);
	}
	assert(sscanf(buff, "%s %s %s", token, name, value) == 3);
	assert(strncmp(token, "struct", strlen(token)) == 0);// If first token is not "struct" then error
	//Back to beginning of where text starts in file
	assert(fseek(fp, offset, SEEK_SET) == 0);
	assert(getline(&buff, &len, fp) != -1);
	do{
		if(strncmp(buff, "\n", strlen(buff)) == 0)
		{
			continue;
		}
		assert(sscanf(buff, "%s %s %s", token, name, value) == 3);
		assert(token != NULL && name != NULL && value != NULL && extra == NULL);

		if(value[strlen(value) - 1] == '\n')
		{
			value[strlen(value) - 1] = '\0';//Replace '\n' at end with '\0'
		}

		assert((strncmp(token, "struct", strlen(token)) == 0 || strncmp(token, "field", strlen(token)) == 0));
		
		assert(strlen(value) <= NAME_LEN);
		
		if(strncmp(token, "struct", strlen(token)) == 0)//If line starts with struct
		{
			structFlag = 1;
			for(i = 0; i < strlen(value); i++) //Check if obj ID is valid integer
			{
				assert(value[i] <= '9' && value[i] >= '0');
			}
			assert(strncmp(name, "B", strlen(name)) == 0 || strncmp(name, "C", strlen(name)) == 0 || strncmp(name, "D", strlen(name)) == 0 || strncmp(name, "A", strlen(name)) == 0);
			
			if(strncmp(name, "A", strlen(name)) == 0)//If at struct A
			{
				flagA = 1;
				while((read = getline(&buff, &len, fp)) != -1)
				{
					if(strncmp(buff, "\n", strlen(buff)) == 0)
					{
						continue;
					}
					assert(sscanf(buff, "%s %s %s", token, name, value) == 3);
					assert(token != NULL && name != NULL && value != NULL && extra == NULL);
					if(value[strlen(value) - 1] == '\n')
					{
						value[strlen(value) - 1] = '\0';//Replace '\n' at end with '\0'
					}
					assert(strlen(value) <= NAME_LEN);
					if(strncmp(token, "field", strlen(token)) == 0)//If line starts with field
					{
						assert(strncmp(name, "string_a", strlen(name)) == 0 || strncmp(name, "ptr_b", strlen(name)) == 0 || strncmp(name, "ptr_c", strlen(name)) == 0 || strncmp(name, "string_d", strlen(name)) == 0 || strncmp(name, "ptr_e", strlen(name)) == 0 || strncmp(name, "num_f", strlen(name)) == 0 || strncmp(name, "num_g", strlen(name)) == 0);
						if(strncmp(name, "string_a", strlen(name)) == 0)//If var name is string_a
						{
							snprintf(objA->string_a, strlen(value), "%s", value);
							countA++;//Increment counter for filled struct members
							//printf("string_a: %s\n", objA->string_a);
						}
						else if(strncmp(name, "ptr_b", strlen(name)) == 0)//If var name is ptr_b
						{
							assert(strncmp(value, "B", strlen(value)) == 0);
							
							offset = ftell(fp);//Get current file offset
							assert(offset != -1L);
							objA->ptr_b = upload_B(fp);//Fill B struct
							fseek(fp, offset, SEEK_SET);//Reset file pointer position
							assert(objA->ptr_b != NULL);//If ptr_b was not filled
							
							countA++;//One more filled struct member
							//printf("ptr_b: %p\n", objA->ptr_b);
						}
						else if(strncmp(name, "ptr_c", strlen(name)) == 0)//If var name is ptr_c
						{
							assert(strncmp(value, "C", strlen(value)) == 0);
							
							offset = ftell(fp);//Get current file  offset
							assert(offset != -1L);
							objA->ptr_c = upload_C(fp);//Fill C struct
							fseek(fp, offset, SEEK_SET);//Reset file pointer position
							assert(objA->ptr_c != NULL);//If ptr_c was not filled
							
							countA++;//One more filled struct member
							//printf("ptr_c: %p\n", objA->ptr_c);
						}
						else if(strncmp(name, "string_d", strlen(name)) == 0)//If var name is string_d
						{
							snprintf(objA->string_d, strlen(value), "%s", value);
							countA++;//One more filled struct member
							//printf("string_d: %s\n", objA->string_d);
						}
						else if(strncmp(name, "ptr_e", strlen(name)) == 0)//If var name is ptr_e
						{
							assert(strncmp(value, "D", strlen(value)) == 0);
							
							offset = ftell(fp);//Get current file offset
							assert(offset != -1L);
							objA->ptr_e = upload_D(fp);//Fill D struct
							fseek(fp, offset, SEEK_SET);//Reset file pointer position
							assert(objA->ptr_e != NULL);//If ptr_e was not filled
							
							countA++;
							//printf("ptr_e: %p\n", objA->ptr_e);
						}
						else if(strncmp(name, "num_f", strlen(name)) == 0)//If var name is num_f
						{

							objA->num_f = strtol(value, &num, 10);
							assert(ERANGE != errno && num != value && ('\n' == *num || '\0' == *num));
							countA++;
							//printf("num_f: %d\n", objA->num_f);
						}
						else if(strncmp(name, "num_g", strlen(name)) == 0)//If var name is num_g
						{
							objA->num_g = strtol(value, &num, 10);
							assert(ERANGE != errno && num != value && ('\n' == *num || '\0' == *num));
							countA++;
							//printf("num_g: %d\n", objA->num_g);
						}
					}
					else
					{
						assert(strncmp(token, "struct", strlen(token)) != 0 || countA == NUM_FIELDS_A);
						rtn = 1;//First token not equal to field or struct
					}
					if(countA == NUM_FIELDS_A)//Finished filling struct A
					{
						free(token);
						token = NULL;
						free(value);
						value = NULL;
						free(name);
						name = NULL;
						free(buff);
						buff = NULL;
						return objA;//Return struct A
					}
					assert(rtn != 1);
				}
			}
		}
		else if(strncmp(token, "field", strlen(token)) == 0 && flagA == 1)
		{
			structFlag = 0;
		}
	}while((read = getline(&buff, &len, fp)) != -1);
	
	fprintf(stderr, "Error: could not fill struct A properly\n");
	free(token);
	token = NULL;
	free(value);
	value = NULL;
	free(name);
	name = NULL;
	free(buff);
	buff = NULL;
	return NULL;//Error: Did not fill struct A
}

/**********************************************************************

    Function    : upload_B 
    Description : For each line in file referenced by fp 
                  Assign value to struct field for object B (ints and strings)
                  or call upload_X function to upload data for struct X
    Inputs      : fp - file pointer for object input file
    Outputs     : objA - pointer to struct B or NULL

***********************************************************************/

struct B *upload_B( FILE *fp )
{
	struct B *objB = (struct B*)malloc(sizeof(struct B));
	memset(objB, 0, sizeof(struct B));
	unsigned char *buff = (unsigned char *)malloc(LINE_SIZE);
	memset(buff, 0, LINE_SIZE);
	unsigned char *token = (unsigned char *)malloc(LINE_SIZE);
	memset(token, 0, LINE_SIZE);
	unsigned char *name = (unsigned char *)malloc(LINE_SIZE);
	memset(name, 0, LINE_SIZE);
	unsigned char *value = (unsigned char *)malloc(LINE_SIZE);
	memset(value, 0, LINE_SIZE);
	unsigned char *extra = NULL;//To test if there are too many tokens on the line
	long offset = 0;//File offset
	int rtn = 0;//Return flag
	int flagA = 0;
	int countA = 0;//To count if all struct members have been filled
	int structFlag = 0;
	int i;
	size_t len = LINE_SIZE;
	char *num;
	ssize_t read;

	assert(fseek(fp, 0L, SEEK_SET) == 0);//Go to beginning of file
	assert(getline(&buff, &len, fp) != -1);
	
	while(strncmp(buff, "\n", strlen(buff)) == 0)
	{
		offset = ftell(fp);
		assert(offset != -1L);
		assert(getline(&buff, &len, fp) != -1);
	}
	assert(sscanf(buff, "%s %s %s", token, name, value) == 3);
	assert(strncmp(token, "struct", strlen(token)) == 0);// If first token is not "struct" then error
	
	//Back to beginning of where text starts in file
	assert(fseek(fp, offset, SEEK_SET) == 0);
	
	assert(getline(&buff, &len, fp) != -1);

	do{
		if(strncmp(buff, "\n", strlen(buff)) == 0)
		{
			continue;
		}
		assert(sscanf(buff, "%s %s %s", token, name, value) == 3);
		assert(token != NULL && name != NULL && value != NULL && extra == NULL);
		
		if(value[strlen(value) - 1] == '\n')
		{
			value[strlen(value) - 1] = '\0';//Replace '\n' at end with '\0'
		}

		assert((strncmp(token, "struct", strlen(token)) == 0 || strncmp(token, "field", strlen(token)) == 0));
		
		assert(strlen(value) <= NAME_LEN);
		
		if(strncmp(token, "struct", strlen(token)) == 0)//If first token is struct
		{
			structFlag = 1;
			for(i = 0; i < strlen(value); i++) //Check if obj ID is valid
			{
				assert(value[i] <= '9' && value[i] >= '0');
			}
			assert(strncmp(name, "B", strlen(name)) == 0 || strncmp(name, "C", strlen(name)) == 0 || strncmp(name, "D", strlen(name)) == 0 || strncmp(name, "A", strlen(name)) == 0);
			
			if(strncmp(name, "B", strlen(name)) == 0)//If at struct B line
			{
				flagA = 1;
				while((read = getline(&buff, &len, fp)) != -1)
				{
					if(strncmp(buff, "\n", strlen(buff)) == 0)
					{
						continue;
					}
					assert(sscanf(buff, "%s %s %s", token, name, value) == 3);
					assert(token != NULL && name != NULL && value != NULL && extra == NULL);
					
					if(value[strlen(value) - 1] == '\n')
					{
						value[strlen(value) - 1] = '\0';//Replace '\n' at end with '\0'
					}

					assert(strlen(value) <= NAME_LEN);
					
					if(strncmp(token, "field", strlen(token)) == 0)//If first token is field
					{
						assert(strncmp(name, "string_b", strlen(name)) == 0 || strncmp(name, "num_a", strlen(name)) == 0 || strncmp(name, "num_c", strlen(name)) == 0);
						if(strncmp(name, "string_b", strlen(name)) == 0)
						{
							snprintf(objB->string_b, strlen(value), "%s", value);
							countA++;
							//printf("string_b: %s\n", objB->string_b);
						}
						else if(strncmp(name, "num_a", strlen(name)) == 0)
						{
							objB->num_a = strtol(value, &num, 10);
							assert(ERANGE != errno && num != value && ('\n' == *num || '\0' == *num));
							countA++;
							//printf("num_a: %d\n", objB->num_a);
						}
						else if(strncmp(name, "num_c", strlen(name)) == 0)
						{
							objB->num_c = strtol(value, &num, 10);
							assert(ERANGE != errno && num != value && ('\n' == *num || '\0' == *num));
							countA++;
							//printf("num_c: %d\n", objB->num_c);
						}
					}
					else
					{
						assert(strncmp(token, "struct", strlen(token)) != 0 || countA == NUM_FIELDS_B);
						rtn = 1;//Token not equal to field or struct
					}
					if(countA == NUM_FIELDS_B)//If all struct member have been filled
					{
						free(token);
						token = NULL;
						free(value);
						value = NULL;
						free(name);
						name = NULL;
						free(buff);
						buff = NULL;
						return objB;
					}
					assert(rtn != 1);
				}

			}
		}
		else if(strncmp(token, "field", strlen(token)) == 0 && flagA == 1)
		{
			structFlag = 0;
		}
	}while((read = getline(&buff, &len, fp)) != -1);

	free(token);
	token = NULL;
	free(value);
	value = NULL;
	free(name);
	name = NULL;
	free(buff);
	buff = NULL;
	return NULL;//Error: Struct B was not filled correctly
}

/**********************************************************************

    Function    : upload_C 
    Description : For each line in file referenced by fp 
                  Assign value to struct field for object C (ints and strings)
                  or call upload_X function to upload data for struct X
    Inputs      : fp - file pointer for object input file
    Outputs     : objA - pointer to struct C or NULL

***********************************************************************/

struct C *upload_C( FILE *fp )
{
	struct C *objC = (struct C*)malloc(sizeof(struct C));
	memset(objC, 0, sizeof(struct C));
	unsigned char *buff = (unsigned char *)malloc(LINE_SIZE);
	memset(buff, 0, LINE_SIZE);
	unsigned char *token = (unsigned char *)malloc(LINE_SIZE);
	memset(token, 0, LINE_SIZE);
	unsigned char *name = (unsigned char *)malloc(LINE_SIZE);
	memset(name, 0, LINE_SIZE);
	unsigned char *value = (unsigned char *)malloc(LINE_SIZE);
	memset(value, 0, LINE_SIZE);
	unsigned char *extra = NULL;//To test if there are too many tokens on the line
	long offset = 0;//File offset
	int rtn = 0;//Return flag
	int flagA = 0;
	int countA = 0;//To count if all struct members have been filled
	int structFlag = 0;
	int i;
	size_t len = LINE_SIZE;
	char *num;
	ssize_t read;

	assert(fseek(fp, 0L, SEEK_SET) == 0);//Go to beginning of file
	assert(getline(&buff, &len, fp) != -1);

	while(strncmp(buff, "\n", strlen(buff)) == 0)
	{
		offset = ftell(fp);
		assert(offset != -1L);
		assert(getline(&buff, &len, fp) != -1);
	}
	assert(sscanf(buff, "%s %s %s", token, name, value) == 3);
	assert(strncmp(token, "struct", strlen(token)) == 0);// If first token is not "struct" then error
	
	//Back to beginning of where text starts in file
	assert(fseek(fp, offset, SEEK_SET) == 0);//Go to beginning of file

	assert(getline(&buff, &len, fp) != -1);
	do{
		if(strncmp(buff, "\n", strlen(buff)) == 0)
		{
			continue;
		}
		assert(sscanf(buff, "%s %s %s", token, name, value) == 3);
		assert(token != NULL && name != NULL && value != NULL && extra == NULL);
		
		if(value[strlen(value) - 1] == '\n')
		{
			value[strlen(value) - 1] = '\0';//Replace '\n' at end with '\0'
		}
		assert((strncmp(token, "struct", strlen(token)) == 0 || strncmp(token, "field", strlen(token)) == 0));
		
		assert(strlen(value) <= NAME_LEN);
		
		if(strncmp(token, "struct", strlen(token)) == 0)//If first token is struct
		{
			structFlag = 1;
			for(i = 0; i < strlen(value); i++) //Check if obj ID is valid
			{
				assert(value[i] <= '9' && value[i] >= '0');
				
			}
			assert(strncmp(name, "B", strlen(name)) == 0 || strncmp(name, "C", strlen(name)) == 0 || strncmp(name, "D", strlen(name)) == 0 || strncmp(name, "A", strlen(name)) == 0);
			
			if(strncmp(name, "C", strlen(name)) == 0)//At struct C line
			{
				flagA = 1;
				while((read = getline(&buff, &len, fp)) != -1)
				{
					if(strncmp(buff, "\n", strlen(buff)) == 0)
					{
						continue;
					}
					assert(sscanf(buff, "%s %s %s", token, name, value) == 3);
					assert(token != NULL && name != NULL && value != NULL && extra == NULL);
					
					if(value[strlen(value) - 1] == '\n')
					{
						value[strlen(value) - 1] = '\0';//Replace '\n' at end with '\0'
					}
					assert(strlen(value) <= NAME_LEN);
					
					if(strncmp(token, "field", strlen(token)) == 0)//If first token is field
					{
						assert(strncmp(name, "string_b", strlen(name)) == 0 || strncmp(name, "num_a", strlen(name)) == 0 || strncmp(name, "num_c", strlen(name)) == 0 || strncmp(name, "string_d", strlen(name)) == 0 || strncmp(name, "string_e", strlen(name)) == 0);
						if(strncmp(name, "string_b", strlen(name)) == 0)
						{
							snprintf(objC->string_b, strlen(value), "%s", value);
							countA++;
							//printf("string_b: %s\n", objC->string_b);
						}
						else if(strncmp(name, "num_a", strlen(name)) == 0)
						{
							objC->num_a = strtol(value, &num, 10);
							assert(ERANGE != errno && num != value && ('\n' == *num || '\0' == *num));
							countA++;
							//printf("num_a: %d\n", objC->num_a);
						}
						else if(strncmp(name, "num_c", strlen(name)) == 0)
						{
							objC->num_c = strtol(value, &num, 10);
							assert(ERANGE != errno && num != value && ('\n' == *num || '\0' == *num));
							countA++;
							//printf("num_c: %d\n", objC->num_c);
						}
						else if(strncmp(name, "string_d", strlen(name)) == 0)
						{
							snprintf(objC->string_d, strlen(value), "%s", value);
							countA++;
							//printf("string_d: %s\n", objC->string_d);
						}
						else if(strncmp(name, "string_e", strlen(name)) == 0)
						{
							snprintf(objC->string_e, strlen(value), "%s", value);
							countA++;
							//printf("string_e: %s\n", objC->string_e);
						}
					}
					else
					{
						assert(strncmp(token, "struct", strlen(token)) != 0 || countA == NUM_FIELDS_C);
						rtn = 1;//First token not equal to field or struct
					}
					if(countA == NUM_FIELDS_C)//If all members of struct C are filled
					{
						free(token);
						token = NULL;
						free(value);
						value = NULL;
						free(name);
						name = NULL;
						free(buff);
						buff = NULL;
						return objC;
					}
					assert(rtn != 1);
				}
			}
		}
		else if(strncmp(token, "field", strlen(token)) == 0 && flagA == 1)
		{
			structFlag = 0;
		}
	}while((read = getline(&buff, &len, fp)) != -1);
	free(token);
	token = NULL;
	free(value);
	value = NULL;
	free(name);
	name = NULL;
	free(buff);
	buff = NULL;
	return NULL;//Error: struct C filled incorrectly
}

/**********************************************************************

    Function    : upload_D 
    Description : For each line in file referenced by fp 
                  Assign value to struct field for object D (ints and strings)
                  or call upload_X function to upload data for struct X
    Inputs      : fp - file pointer for object input file
    Outputs     : objA - pointer to struct D or NULL

***********************************************************************/

struct D *upload_D( FILE *fp )
{
	struct D *objD = (struct D*)malloc(sizeof(struct D));
	memset(objD, 0, sizeof(struct D));
	unsigned char *buff = (unsigned char *)malloc(LINE_SIZE);
	memset(buff, 0, LINE_SIZE);
	unsigned char *token = (unsigned char *)malloc(LINE_SIZE);
	memset(token, 0, LINE_SIZE);
	unsigned char *name = (unsigned char *)malloc(LINE_SIZE);
	memset(name, 0, LINE_SIZE);
	unsigned char *value = (unsigned char *)malloc(LINE_SIZE);
	memset(value, 0, LINE_SIZE);
	unsigned char *extra = NULL;//To test if there are too many tokens on the line
	long offset = 0;//File offset
	int rtn = 0;//Return flag
	int flagA = 0;
	int countA = 0;//To count if all struct members have been filled
	int structFlag = 0;
	int i;
	size_t len = LINE_SIZE;
	char *num;
	ssize_t read;

	assert(fseek(fp, 0L, SEEK_SET) == 0);//Go to beginning of file
	assert(getline(&buff, &len, fp) != -1);

	while(strncmp(buff, "\n", strlen(buff)) == 0)//While line is empty
	{
		offset = ftell(fp);
		assert(offset != -1L);
		assert(getline(&buff, &len, fp) != -1);
	}
	assert(sscanf(buff, "%s %s %s", token, name, value) == 3);
	assert(strncmp(token, "struct", strlen(token)) == 0);// If first token is not "struct", then error
	
	//Back to beginning of where text starts in file
	assert(fseek(fp, offset, SEEK_SET) == 0);
	assert(getline(&buff, &len, fp) != -1);

	do{
		if(strncmp(buff, "\n", strlen(buff)) == 0)
		{
			continue;
		}
		assert(sscanf(buff, "%s %s %s", token, name, value) == 3);
		assert(token != NULL && name != NULL && value != NULL && extra == NULL);
		
		if(value[strlen(value) - 1] == '\n')
		{
			value[strlen(value) - 1] = '\0';//Replace '\n' at end with '\0'
		}

		assert((strncmp(token, "struct", strlen(token)) == 0 || strncmp(token, "field", strlen(token)) == 0));
		
		assert(strlen(value) <= NAME_LEN);
		
		if(strncmp(token, "struct", strlen(token)) == 0)//If first token is struct
		{
			structFlag = 1;
			for(i = 0; i < strlen(value); i++) //Check if obj ID is valid
			{
				assert(value[i] <= '9' && value[i] >= '0');//Check if objID is an int
			}
			assert(strncmp(name, "B", strlen(name)) == 0 || strncmp(name, "C", strlen(name)) == 0 || strncmp(name, "D", strlen(name)) == 0 || strncmp(name, "A", strlen(name)) == 0);
			if(strncmp(name, "D", strlen(name)) == 0)//If at struct D line
			{
				flagA = 1;
				
				while((read = getline(&buff, &len, fp)) != -1)
				{
					if(strncmp(buff, "\n", strlen(buff)) == 0)
					{
						continue;
					}
					assert(sscanf(buff, "%s %s %s", token, name, value) == 3);
					assert(token != NULL && name != NULL && value != NULL && extra == NULL);
					
					if(value[strlen(value) - 1] == '\n')
					{
						value[strlen(value) - 1] = '\0';//Replace '\n' at end with '\0'
					}
					assert(strlen(value) <= NAME_LEN);
					
					if(strncmp(token, "field", strlen(token)) == 0)//If first token is field
					{
						assert(strncmp(name, "string_a", strlen(name)) == 0 || strncmp(name, "num_e", strlen(name)) == 0 || strncmp(name, "string_b", strlen(name)) == 0 || strncmp(name, "string_c", strlen(name)) == 0 || strncmp(name, "string_d", strlen(name)) == 0);
						if(strncmp(name, "string_a", strlen(name)) == 0)
						{
							snprintf(objD->string_a, strlen(value), "%s", value);
							countA++;
							//printf("string_a: %s\n", objD->string_a);
						}
						else if(strncmp(name, "num_e", strlen(name)) == 0)
						{
							objD->num_e = strtol(value, &num, 10);
							assert(ERANGE != errno && num != value && ('\n' == *num || '\0' == *num));
							countA++;
							//printf("num_e: %d\n", objD->num_e);
						}
						else if(strncmp(name, "string_b", strlen(name)) == 0)
						{
							snprintf(objD->string_b, strlen(value), "%s", value);
							countA++;
							//printf("string_b: %s\n", objD->string_b);
						}
						else if(strncmp(name, "string_c", strlen(name)) == 0)
						{
							snprintf(objD->string_c, strlen(value), "%s", value);
							countA++;
							//printf("string_c: %s\n", objD->string_c);
						}
						else if(strncmp(name, "string_d", strlen(name)) == 0)
						{
							snprintf(objD->string_d, strlen(value), "%s", value);
							countA++;
							//printf("string_d: %s\n", objD->string_d);
						}
					}
					else
					{
						assert(strncmp(token, "struct", strlen(token)) != 0 || countA == NUM_FIELDS_D);
						rtn = 1;//First token not equal to field or struct
					}
					if(countA == NUM_FIELDS_D)//If all members of struct D are filled
					{
						free(token);
						token = NULL;
						free(value);
						value = NULL;
						free(name);
						name = NULL;
						free(buff);
						buff = NULL;
						return objD;
					}
					assert(rtn != 1);
				}

			}
		}
		else if(strncmp(token, "field", strlen(token)) == 0 && flagA == 1)
		{
			structFlag = 0;
		}
	}while((read = getline(&buff, &len, fp)) != -1);

	free(token);
	token = NULL;
	free(value);
	value = NULL;
	free(name);
	name = NULL;
	free(buff);
	buff = NULL;
	return NULL;//Error: struct D filled incorrectly
}

/**********************************************************************

    Function    : marshall
    Description : serialize the object data to store in KVS
            *** Below an example is provided for a different object structure ***
            *** Adapt for your object structure ***
    Inputs      : objA - reference to root structure of object
    Outputs     : unsigned char string of serialized object

***********************************************************************/

unsigned char *marshall( struct A *objA )
{
	unsigned char *obj = (unsigned char *)malloc(OBJ_LEN);

	memcpy( obj, &(objA->string_a), sizeof(objA->string_a) );
	memcpy( obj+sizeof(objA->string_a), objA->ptr_b, sizeof(struct B));
	memcpy( obj+sizeof(objA->string_a)+sizeof(struct B), objA->ptr_c, sizeof(struct C));
	memcpy( obj+sizeof(objA->string_a)+sizeof(struct B)+sizeof(struct C), &(objA->string_d), sizeof(objA->string_d));
	memcpy( obj+sizeof(objA->string_a)+sizeof(struct B)+sizeof(struct C)+sizeof(objA->string_d), objA->ptr_e, sizeof(struct D));
	memcpy( obj+sizeof(objA->string_a)+sizeof(struct B)+sizeof(struct C)+sizeof(objA->string_d)+sizeof(struct D), &(objA->num_f), sizeof(objA->num_f));
	memcpy( obj+sizeof(objA->string_a)+sizeof(struct B)+sizeof(struct C)+sizeof(objA->string_d)+sizeof(struct D)+sizeof(objA->num_f), &(objA->num_g), sizeof(objA->num_g));
	
	printf("Size of object = %lu\n", 
	       sizeof(objA->string_a)+sizeof(struct B)+sizeof(struct C)+sizeof(struct D)+
	       sizeof(objA->string_d)+sizeof(objA->num_f)+sizeof(objA->num_g));
 
	return obj;
}


/**********************************************************************

    Function    : unmarshall
    Description : convert a serialized object into data structure form
            *** Below an example is provided for a different object structure ***
            *** Adapt for your object structure ***
    Inputs      : obj - unsigned char string of serialized object
    Outputs     : reference to root structure of object

***********************************************************************/

struct A *unmarshall( unsigned char *obj )
{
	struct A *objA = (struct A *)malloc(sizeof(struct A));
	struct B *objB = (struct B *)malloc(sizeof(struct B));
	struct C *objC = (struct C *)malloc(sizeof(struct C));
	struct D *objD = (struct D *)malloc(sizeof(struct D));

	memcpy( &(objA->string_a), obj, sizeof(objA->string_a) );
	memcpy( objB, obj+sizeof(objA->string_a), sizeof(struct B));
	memcpy( objC, obj+sizeof(objA->string_a)+sizeof(struct B), sizeof(struct C));
	memcpy( &(objA->string_d), obj+sizeof(objA->string_a)+sizeof(struct B)+sizeof(struct C), sizeof(objA->string_d));
	memcpy( objD, obj+sizeof(objA->string_a)+sizeof(struct B)+sizeof(struct C)+sizeof(objA->string_d), sizeof(struct D));
	memcpy( &(objA->num_f), obj+sizeof(objA->string_a)+sizeof(struct B)+sizeof(struct C)+sizeof(objA->string_d)+sizeof(struct D), sizeof(objA->num_f));
	memcpy( &(objA->num_g), obj+sizeof(objA->string_a)+sizeof(struct B)+sizeof(struct C)+sizeof(objA->string_d)+sizeof(struct D)+sizeof(objA->num_f), sizeof(objA->num_g));


	objA->ptr_b = objB;
	objA->ptr_c = objC;
	objA->ptr_e = objD;

	return objA;
}


/**********************************************************************

    Function    : output_obj
    Description : print int and string fields from structs A, B, and last
            *** Below an example is provided for a different object structure ***
            *** Adapt for your object structure ***
    Inputs      : objA - reference to root structure of object
                  id - identifier for the object
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int output_obj( struct A *objA, char *id )
{
	// Base object fields
	printf("ObjA: %s\n", id );
	printf("ObjA -> string_a: %s\n", objA->string_a );
	printf("ObjA -> string_d: %s\n", objA->string_d );
	printf("ObjA -> num_f: %d\n", objA->num_f );
	printf("ObjA -> num_g: %d\n", objA->num_g );


	// First sub-object fields
	printf("ObjB -> num_a: %d\n", objA->ptr_b->num_a );
	printf("ObjB -> string_b: %s\n", objA->ptr_b->string_b );
	printf("ObjB -> num_c: %d\n", objA->ptr_b->num_c );


	//Second sub-object fields
	printf("ObjC -> num_a: %d\n", objA->ptr_c->num_a );
	printf("ObjC -> string_b: %s\n", objA->ptr_c->string_b );
	printf("ObjC -> num_c: %d\n", objA->ptr_c->num_c );
	printf("ObjC -> string_d: %s\n", objA->ptr_c->string_d );
	printf("ObjC -> string_e: %s\n", objA->ptr_c->string_e );

	// Last sub-object fields
	printf("ObjD -> string_a: %s\n", objA->ptr_e->string_a );
	printf("ObjD -> string_b: %s\n", objA->ptr_e->string_b );
	printf("ObjD -> string_c: %s\n", objA->ptr_e->string_c );
	printf("ObjD -> string_d: %s\n", objA->ptr_e->string_d );
	printf("ObjD -> num_e: %d\n", objA->ptr_e->num_e );

	return 0;
}

/**********************************************************************

    Function    : kvs_dump
    Description : dump the KVS to a file specified by path
    Inputs      : kvs - key value store
                  path - file path to dump KVS
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int kvs_dump( struct kvs *kvs, char *path )
{
	int i;
	struct kv_list_entry *kvle;
	struct authval *av;
	struct kvpair *kvp;
	FILE *fp = fopen( path, "w+" ); 

	assert( fp != NULL );

	for (i = 0; i < KVS_BUCKETS; i++) {
		kvle = kvs->store[i];
      
		while ( kvle != NULL ) {
			kvp = kvle->entry;
			av = kvp->av;

			fwrite((const char *)kvp->key, 1, kvs->keysize, fp);
			fwrite((const char *)av->value, 1, kvs->valsize, fp);
			fwrite((const char *)av->tag, 1, kvs->tagsize, fp);
			fwrite((const char *)PADDING, 1, PAD_LEN, fp);
	
			// Next entry
			kvle = kvle->next;
		}
	}
	return 0;
}
