#define STRLEN   16

struct A {
	char string_a[STRLEN]; // Capitalize Strings
	struct B *ptr_b; // 
	struct C *ptr_c; // 
	char string_d[STRLEN]; // Capitalize Strings
	struct D *ptr_e; // 
	int num_f; // Any integer
	int num_g; // Any integer
};
struct B {
	int num_a; // <0 or set to 0
	char string_b[STRLEN]; // Must have vowel or add to end
	int num_c; // >0 or set to 0
};
struct C {
	int num_a; // Any integer
	char string_b[STRLEN]; // Any string
	int num_c; // >0 or set to 0
	char string_d[STRLEN]; // Any string
	char string_e[STRLEN]; // Must have vowel or add to end
};
struct D {
	char string_a[STRLEN]; // Capitalize Strings
	char string_b[STRLEN]; // Any string
	char string_c[STRLEN]; // Capitalize Strings
	char string_d[STRLEN]; // Any string
	int num_e; // <0 or set to 0
};
