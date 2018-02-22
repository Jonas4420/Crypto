#include <vector>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/Utils.hpp"
#include "crypto/BigNum.hpp"

static int
rnd_std_rand(void *state, uint8_t *data, std::size_t data_sz)
{
	((void)state);

	for ( std::size_t i = 0 ; i < data_sz ; ++i ) {
		data[i] = rand();
	}

	return 0;
}

static int
rnd_broken(void *state, uint8_t *data, std::size_t data_sz)
{
	static int call = 0;

	int *ptr_fail = static_cast<int*>(state);
	int fail = ptr_fail ? *ptr_fail : 0;

	// Failure if number of calls reached the limit
	if ( fail == call ) {
		call = 0;
		return 1;
	}

	++call;

	for ( std::size_t i = 0 ; i < data_sz ; ++i ) {
		data[i] = rand();
	}

	return 0;
}

TEST(BigNum, constructors)
{
	// Empty constructor
	{
		Crypto::BigNum X;

		EXPECT_THAT(X.get_bit(42), 0);
		EXPECT_THAT(X.lsb(),       0);
		EXPECT_THAT(X.bitlen(),    0);
		EXPECT_THAT(X.size(),      1);
	}

	// Int constructor
	{
		int val     = 42;
		int val_neg = -val;

		Crypto::BigNum X(val);

		EXPECT_EQ(X, val);
		EXPECT_NE(X, val_neg);

		Crypto::BigNum Y(val_neg);

		EXPECT_EQ(Y, val_neg);
		EXPECT_NE(Y, val);
	}

	// Copy constructor
	{
		int val     = 42;
		int val_neg = -val;

		Crypto::BigNum X(val);

		EXPECT_EQ(X, val);
		EXPECT_NE(X, val_neg);

		Crypto::BigNum Y(X);

		EXPECT_EQ(Y, val);
		EXPECT_NE(Y, val_neg);
	}

	// Move constructor
	{
		int val     = 42;
		int val_neg = -val;

		Crypto::BigNum X(val);
		EXPECT_EQ(X, val);
		EXPECT_NE(X, val_neg);

		Crypto::BigNum Y(std::move(X));

		EXPECT_NE(X, val);
		EXPECT_NE(X, val_neg);

		EXPECT_EQ(Y, val);
		EXPECT_NE(Y, val_neg);
	}

	// Copy assignment operator
	{
		int val     = 42;
		int val_neg = -val;

		Crypto::BigNum X(val);
		EXPECT_EQ(X, val);
		EXPECT_NE(X, val_neg);

		Crypto::BigNum Y;
		EXPECT_NE(Y, val);
		EXPECT_NE(Y, val_neg);

		Y = X;

		EXPECT_EQ(Y, val);
		EXPECT_NE(Y, val_neg);
	}

	// Move assignment operator
	{
		int val     = 42;
		int val_neg = -val;

		Crypto::BigNum X(val);
		EXPECT_EQ(X, val);
		EXPECT_NE(X, val_neg);

		Crypto::BigNum Y;
		EXPECT_NE(Y, val);
		EXPECT_NE(Y, val_neg);

		Y = std::move(X);

		EXPECT_NE(X, val);
		EXPECT_NE(X, val_neg);

		EXPECT_EQ(Y, val);
		EXPECT_NE(Y, val_neg);
	}

	// BigNum too big
	{
		std::string exception, expected("Memory allocation failed");
		uint8_t data[(sizeof(std::size_t) * 10000) + 1];
		std::size_t data_sz = sizeof(data);

		memset(data, 0x00, data_sz);

		try {
			Crypto::BigNum X(data, data_sz);
		} catch ( const Crypto::BigNum::Exception &bne ) {
			exception = bne.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(BigNum, read_binary)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"0941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290"
			"ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889"
			"af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424",
			"5612568098175228233414189632037248949061396369355639252081601789"
			"2111350604111697682705498319512049040516698827829292076808006940"
			"8739749795845270734810126360163539134623767555567200198311873649"
			"93587901952757307830896531678727717924"
		}
	};

	for ( auto test : tests ) {
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		Crypto::Utils::from_hex(test[0], data, data_sz);
		Crypto::BigNum X(data, data_sz);

		Crypto::BigNum Y(test[0], 16);
		EXPECT_EQ(X, Y);

		Crypto::BigNum Z(test[1], 10);
		EXPECT_EQ(X, Z);
	}
}

TEST(BigNum, copy)
{
	// Copy other
	{
		Crypto::BigNum X("0");
		Crypto::BigNum Y("1500");
		Crypto::BigNum A("1500");

		EXPECT_NE(X, Y);
		EXPECT_EQ(Y, A);

		Y = X;

		EXPECT_EQ(X, Y);
		EXPECT_NE(Y, A);
	}

	// Copy self
	{
		int val = 14;
		Crypto::BigNum X(14);

		X = X;

		EXPECT_EQ(X, val);
	}
}

TEST(BigNum, safe_cond_assign)
{
	const std::vector<std::vector<std::string>> tests = {
		{                   "01", "+",                   "02", "+" },
		{                   "01", "+",                   "02", "-" },
		{                   "01", "-",                   "02", "+" },
		{                   "01", "-",                   "02", "-" },
		{ "FF000000000000000001", "+",                   "02", "+" },
		{                   "01", "+", "FF000000000000000002", "+" }
	};

	for ( auto test : tests ) {
		Crypto::BigNum X(test[0], 16);
		if ( test[1] == "-" ) { X = -X; }
		Crypto::BigNum Y(test[2], 16);
		if ( test[3] == "-" ) { Y = -Y; }

		Crypto::BigNum XX(X);

		X.safe_cond_assign(Y, false);
		EXPECT_EQ(X, XX);
		
		X.safe_cond_assign(Y, true);
		EXPECT_EQ(X, Y);
	}
}

TEST(BigNum, safe_cond_swap)
{
	const std::vector<std::vector<std::string>> tests = {
		{                   "01", "+",                   "02", "+" },
		{                   "01", "+",                   "02", "-" },
		{                   "01", "-",                   "02", "+" },
		{                   "01", "-",                   "02", "-" },
		{ "FF000000000000000001", "+",                   "02", "+" },
		{                   "01", "+", "FF000000000000000002", "+" }
	};

	for ( auto test : tests ) {
		Crypto::BigNum X(test[0], 16);
		if ( test[1] == "-" ) { X = -X; }
		Crypto::BigNum Y(test[2], 16);
		if ( test[3] == "-" ) { Y = -Y; }

		Crypto::BigNum XX(X);
		Crypto::BigNum YY(Y);

		X.safe_cond_swap(Y, false);
		EXPECT_EQ(X, XX);
		EXPECT_EQ(Y, YY);

		X.safe_cond_swap(Y, true);
		EXPECT_EQ(Y, XX);
		EXPECT_EQ(X, YY);
	}
}

TEST(BigNum, cmp)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "693",           "693",  "0" },
		{ "693",           "692",  "1" },
		{ "693",           "694", "-1" },
		{ "-2",             "-2",  "0" },
		{ "-2",             "-3",  "1" },
		{ "-2",             "-1", "-1" },
		{ "-3",              "2", "-1" },
		{ "2",              "-3",  "1" },
		{ "-2", "31231231289798", "-1" }
	};

	for ( auto test : tests ) {
		Crypto::BigNum X(test[0]);
		Crypto::BigNum Y(test[1]);

		if ( test[2] == "0" ) {
			EXPECT_TRUE(X == Y);
		} else if ( test[2] == "1" ) {
			EXPECT_TRUE(X > Y);
		} else if ( test[2] == "-1" ) {
			EXPECT_TRUE(X < Y);
		}
	}
}

TEST(BigNum, cmp_int)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "693", "693",  "0" },
		{ "693", "692",  "1" },
		{ "693", "694", "-1" },
		{ "-2",   "-2",  "0" },
		{ "-2",   "-3",  "1" },
		{ "-2",   "-1", "-1" }
	};

	for ( auto test : tests ) {
		Crypto::BigNum X(test[0]);
		int Y = atoi(test[1].c_str());

		if ( test[2] == "0" ) {
			EXPECT_TRUE(X == Y);
		} else if ( test[2] == "1" ) {
			EXPECT_TRUE (X > Y);
		} else if ( test[2] == "-1" ) {
			EXPECT_TRUE(X < Y);
		}
	}
}

TEST(BigNum, inc)
{
	const std::vector<std::vector<std::string>> tests = {
		{  "1",  "2" },
		{ "-1",  "0" },
		{ "-2", "-1" }
	};

	// Prefix incrementation
	for ( auto test : tests ) {
		Crypto::BigNum A, B, C;

		A = Crypto::BigNum(test[0]);
		B = Crypto::BigNum(test[1]);

		C = ++A;
		EXPECT_EQ(A, B);
		EXPECT_EQ(C, B);
	}

	// Postfix incrementation
	for ( auto test : tests ) {
		Crypto::BigNum A, B, C, D;

		A = Crypto::BigNum(test[0]);
		B = Crypto::BigNum(test[1]);

		D = A;
		C = A++;

		EXPECT_EQ(A, B);
		EXPECT_EQ(C, D);
	}
}

TEST(BigNum, add)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "12345678",   "642531",  "12988209" },
		{ "-12345678",  "642531", "-11703147" },
		{ "12345678",  "-642531",  "11703147" },
		{ "-12345678", "-642531", "-12988209" },
		{
			"2039568783564019774057658669290345772801939933143482630947726464"
			"5328306272270127763293661606314408817331237288267712387953870940"
			"0158306567338328279154499698366071906766440037074217117805690872"
			"7928481491120222863321448761833763265120835748216479339929612499"
			"17319836219304274280243803104015000563790123",
			"5318722890542041841850847343751333994083036139821308566452994649"
			"3095217860604584887712914782038799642817556422820478584614120753"
			"2462936339834139412401975338705794646595487324365194792822189473"
			"0922739935805879645716596780844841526038810941769955948133022842"
			"32006001752128168901293560051833646881436219",
			"7358291674106061615908506013041679766884976072964791197400721113"
			"8423524132874712651006576388353208460148793711088190972567991693"
			"2621242907172467691556475037071866553361927361439411910627880345"
			"8851221426926102509038045542678604791159646689986435288062635341"
			"49325837971432443181537363155848647445226342"
		}, {
			"6438080068035544392301298549614926991513861075340134329180734395"
			"2413826484237063006136971539473913409092293733259038472039713333"
			"5969549256322620979036686633213903952966175107096769180017646161"
			"851573147596390153",
			"5612568098175228233349808831356893505138383383859489982166463178"
			"4577337171193624243181360054669678410455329112434552942717084003"
			"5413845948641299401450430867600312924833400689235061158782211898"
			"86491132772739661669044958531131327771",
			"5612568098175228233414189632037248949061396369355639252081601789"
			"2111350604111697682705498319512049040516698827829292076808006940"
			"8739749795845270734810126360163539134623767555567200198311873649"
			"93587901952757307830896531678727717924"
		}
	};

	for ( auto test : tests ) {
		Crypto::BigNum X(test[0]);
		Crypto::BigNum Y(test[1]);
		Crypto::BigNum A(test[2]);

		Crypto::BigNum Z = X + Y;

		EXPECT_EQ(Z, A);
	}
}

TEST(BigNum, add_inplace)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"12345678", "10",
			"24691356", "10"
		}, {
			"ffffffffffffffffffffffffffffffff",   "16",
			"01fffffffffffffffffffffffffffffffe", "16"
		}, {
			"6438080068035544392301298549614926991513861075340134329180734395"
			"2413826484237063006136971539473913409092293733259038472039713333"
			"5969549256322620979036686633213903952966175107096769180017646161"
			"851573147596390153",
			"10",
			"1287616013607108878460259709922985398302772215068026865836146879"
			"0482765296847412601227394307894782681818458746651807694407942666"
			"7193909851264524195807337326642780790593235021419353836003529232"
			"3703146295192780306",
			"10"
		}
	};

	for ( auto test : tests ) {
		Crypto::BigNum X(test[0], atoi(test[1].c_str()));
		Crypto::BigNum Y(test[0], atoi(test[1].c_str()));
		Crypto::BigNum Z(test[0], atoi(test[1].c_str()));
		Crypto::BigNum A(test[2], atoi(test[3].c_str()));

		X -= X.abs();
		EXPECT_EQ(X, 0);

		Y += Y.abs();
		EXPECT_EQ(Y, A);

		Z += Z;
		EXPECT_EQ(Z, A);
	}
}

TEST(BigNum, dec)
{
	const std::vector<std::vector<std::string>> tests = {
		{  "2",  "1" },
		{  "0", "-1" },
		{ "-1", "-2" }
	};

	Crypto::BigNum A, B, C, D;

	// Prefix incrementation
	for ( auto test : tests ) {
		A = Crypto::BigNum(test[0]);
		B = Crypto::BigNum(test[1]);

		C = --A;
		EXPECT_EQ(A, B);
		EXPECT_EQ(C, B);
	}

	// Postfix incrementation
	for ( auto test : tests ) {
		A = Crypto::BigNum(test[0]);
		B = Crypto::BigNum(test[1]);

		D = A;
		C = A--;

		EXPECT_EQ(A, B);
		EXPECT_EQ(C, D);
	}
}

TEST(BigNum, sub)
{
	const std::vector<std::vector<std::string>> tests = {
		{  "5",  "7",  "-2" },
		{ "-5", "-7",   "2" },
		{ "-5",  "7", "-12" },
		{  "5", "-7",  "12" },
		{
			"5318722890542041841850847343751333994083036139821308566452994649"
			"3095217860604584887712914782038799642817556422820478584614120753"
			"2462936339834139412401975338705794646595487324365194792822189473"
			"0922739935805879645716596780844841526038810941769955948133022842"
			"32006001752128168901293560051833646881436219",
			"2039568783564019774057658669290345772801939933143482630947726464"
			"5328306272270127763293661606314408817331237288267712387953870940"
			"0158306567338328279154499698366071906766440037074217117805690872"
			"7928481491120222863321448761833763265120835748216479339929612499"
			"17319836219304274280243803104015000563790123",
			"3279154106978022067793188674460988221281096206677825935505268184"
			"7766911588334457124419253175724390825486319134552766196660249813"
			"2304629772495811133247475640339722739829047287290977675016498600"
			"2994258444685656782395148019011078260917975193553476608203410343"
			"14686165532823894621049756947818646317646096"
		}, {
			"6438080068035544392301298549614926991513861075340134329180734395"
			"2413826484237063006136971539473913409092293733259038472039713333"
			"5969549256322620979036686633213903952966175107096769180017646161"
			"851573147596390153",
			"5612568098175228233349808831356893505138383383859489982166463178"
			"4577337171193624243181360054669678410455329112434552942717084003"
			"5413845948641299401450430867600312924833400689235061158782211898"
			"86491132772739661669044958531131327771",
			"-561256809817522823328542803067653806121537039836334071225132456"
			"7704332373827555080365722178982730778039395939703981380862616106"
			"6208794210143732806809073537503708671504303382290292211925255014"
			"779394363592722015507193385383534937618"
		}
	};

	for ( auto test : tests ) {
		Crypto::BigNum X(test[0]);
		Crypto::BigNum Y(test[1]);
		Crypto::BigNum A(test[2]);

		Crypto::BigNum Z = X - Y;

		EXPECT_EQ(Z, A);
	}
}

TEST(BigNum, mul)
{
	const std::vector<std::vector<std::string>> tests = {
		{  "5",  "7",  "35" },
		{  "5", "-7", "-35" },
		{ "-5",  "7", "-35" },
		{ "-5", "-7",  "35" },
		{
			"2891171001732020596616782072531323436153525916304586798627747814"
			"5081076845846493521348693253530011243988160148063424837895971948"
			"2441678672369239195069623121858299144829934789476574723514613367"
			"2964148506932363542469293027888892345006054646588349094426514785"
			"1036817433970984747733020522259537",
			"1647158189170179476470400971905734999627023994899345226881297503"
			"7240586099924712715366967486587417803753916334331355573776945238"
			"8715120268328106262261643463288074076693660299262214153835608143"
			"3882844964226537782275976801140675706106352476814056786735020855"
			"4439342320410551341675119078050953",
			"4762215991794248876695158292312232639393421356817916058425404293"
			"2103814463332394124870640537572348291253519236384511615423646518"
			"4147599697841273424891410002781967962186252583311115708128167171"
			"2622069195145878998835472796470259528375163246496569135804116112"
			"9731267895580189953693757747681966786105306343290607131572794882"
			"6276092545739432005962781562403795455162483159362585281248265005"
			"4417150801978003357578715880459597545478368259771691258663241284"
			"4969987707676231676812781607458776679901862617919977618849008710"
			"3869164122906791440101822594139648973454716256383294690817576188"
			"761"
		}
	};

	for ( auto test : tests ) {
		Crypto::BigNum X(test[0]);
		Crypto::BigNum Y(test[1]);
		Crypto::BigNum A(test[2]);

		Crypto::BigNum Z = X * Y;

		EXPECT_EQ(Z, A);
	}
}

TEST(BigNum, div)
{
	const std::vector<std::vector<std::string>> tests = {
		{  "777",   "7", "111",  "0" },
		{ "1000",  "13",  "76", "12" },
		{ "1000", "-13", "-76", "12" },
		{ "1000",   "7", "142",  "6" },
		{
			"2013305664251822604231073010137627848354723913012380633805538780"
			"3943342738063359782107667328",
			"34",
			"5921487247799478247738450029816552495160952685330531275898643471"
			"74804198178334111238460803",
			"26"
		}, {
			"4762215991794248876695158292312232639393421356817916058425404293"
			"2103814463332394124870640537572348291253519236384511615423646518"
			"4147599697841273424891410002781967962186252583311115708128167171"
			"2622069195145878998835472796470259528375163246496569135804116112"
			"9731267895580189953693757747681966786105306343290607131572794882"
			"6276092545739432005962781562403795455162483159362585281248265005"
			"4417150801978003357578715880459597545478368259771691258663241284"
			"4969987707676231676812781607458776679901862617919977618849008710"
			"3869164122906791440101822594139648973454716256383294690817576188"
			"762",
			"2891171001732020596616782072531323436153525916304586798627747814"
			"5081076845846493521348693253530011243988160148063424837895971948"
			"2441678672369239195069623121858299144829934789476574723514613367"
			"2964148506932363542469293027888892345006054646588349094426514785"
			"1036817433970984747733020522259537",
			"1647158189170179476470400971905734999627023994899345226881297503"
			"7240586099924712715366967486587417803753916334331355573776945238"
			"8715120268328106262261643463288074076693660299262214153835608143"
			"3882844964226537782275976801140675706106352476814056786735020855"
			"4439342320410551341675119078050953",
			"1"
		}
	};

	for ( auto test : tests ) {
		Crypto::BigNum X(test[0]);
		Crypto::BigNum Y(test[1]);
		Crypto::BigNum A(test[2]);
		Crypto::BigNum B(test[3]);

		auto result = X.div_mod(Y);
		Crypto::BigNum Q = result.first;
		Crypto::BigNum R = result.second;

		EXPECT_EQ(Q,  A);
		EXPECT_EQ(R,  B);
	}
}

TEST(BigNum, div_abnormal)
{
	// Division by 0
	{
		std::string exception, expected("Illegal division by 0");
		try {
			Crypto::BigNum X("1000");
			Crypto::BigNum Y("0");

			Crypto::BigNum Z = X / Y;
		} catch ( const Crypto::BigNum::Exception &bne ) {
			exception = bne.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(BigNum, mod)
{
	const std::vector<std::vector<std::string>> tests = {
		{  "1000", "13", "12" },
		{ "-1000", "13",  "1" }
	};

	for ( auto test : tests ) {
		Crypto::BigNum X(test[0]);
		Crypto::BigNum Y(test[1]);
		Crypto::BigNum A(test[2]);

		Crypto::BigNum Z = X % Y;

		EXPECT_EQ(Z, A);
	}
}

TEST(BigNum, mod_abnormal)
{
	// Modulus by 0
	{
		std::string exception, expected("Illegal division by 0");
		try {
			Crypto::BigNum X("1000");
			Crypto::BigNum Y("0");

			Crypto::BigNum Z = X % Y;
		} catch ( const Crypto::BigNum::Exception &bne ) {
			exception = bne.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Negative modulus #1
	{
		std::string exception, expected("Invalid value for modulus");
		try {
			Crypto::BigNum X("1000");
			Crypto::BigNum Y("-13");

			Crypto::BigNum Z = X % Y;
		} catch ( const Crypto::BigNum::Exception &bne ) {
			exception = bne.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Negative modulus #2
	{
		std::string exception, expected("Invalid value for modulus");
		try {
			Crypto::BigNum X("-1000");
			Crypto::BigNum Y("-13");

			Crypto::BigNum Z = X % Y;
		} catch ( const Crypto::BigNum::Exception &bne ) {
			exception = bne.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(BigNum, exp_mod)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "10",           "23",          "13",    "29", "24" },
		{ "10",          "-23",          "13",    "29",  "5" },
		{ "10", "-10000000000", "10000000000", "99999",  "1" },
		{
			"10",
			"4330192409103774782173735729595601098196486470160965605237690108"
			"8117286908333828557375657455739586296509501648386781304366398194"
			"6477698466501451832407592327356331263124555137732393938242285782"
			"144928753919588632679050799198937132922145084847",
			"5781538327977828897150909166778407659250458379645823062042492461"
			"5767585267574909100736280086139775505463827747755708881300297635"
			"7152869957471758322893953596023446423088257361593038497910037910"
			"2915657483866755371559811718767760594919456971354184113721",
			"5831370077972769239568912162160221440520440913113886016529614095"
			"5751642161287457155441560674647910579583314558395962211741853116"
			"6391184939066520869800857530421873250114773204354963864729386957"
			"4272764486830924919475669920771365530662732077771343033977246791"
			"38833126700957",
			"1145974492766843551449206700071479532326594363801634615531869401"
			"1392977719601816414970356647293657889099104934445920419988825490"
			"7113495794730452699842273939581048142004834330369483813876618772"
			"5788690832480616164443920916937870396363168455122921270978650262"
			"90173004860736"
		}, {
			"16",
			"-9f13012cd92aa72fb86ac8879d2fde4f7fd661aaae43a00971f081cc60ca277"
			"059d5c37e89652e2af2585d281d66ef6a9d38a117e9608e9e7574cd142dc5527"
			"8838a2161dd56db9470d4c1da2d5df15a908ee2eb886aaa890f23be16de59386"
			"663a12f1afbb325431a3e835e3fd89b98b96a6f77382f458ef9a37e1f84a0304"
			"5c8676ab55291a94c2228ea15448ee96b626b998",
			"40a54d1b9e86789f06d9607fb158672d64867665c73ee9abb545fc7a785634b3"
			"54c7bae5b962ce8040cf45f2c1f3d3659b2ee5ede17534c8fc2ec85c815e8df1"
			"fe7048d12c90ee31b88a68a081f17f0d8ce5f4030521e9400083bcea73a42903"
			"1d4ca7949c2000d597088e0c39a6014d8bf962b73bb2e8083bd0390a4e00b9b3",
			"eeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576"
			"d674df7496ea81d3383b4813d692c6e0e0d5d8e250b98be48e495c1d6089dad1"
			"5dc7d7b46154d6b6ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec"
			"68edbc3c05726cc02fd4cbf4976eaa9afd5138fe8376435b9fc61d2fc0eb06e3",
			"21acc7199e1b90f9b4844ffe12c19f00ec548c5d32b21c647d48b6015d8eb9ec"
			"9db05b4f3d44db4227a2b5659c1a7cceb9d5fa8fa60376047953ce7397d90aae"
			"b7465e14e820734f84aa52ad0fc66701bcbb991d57715806a11531268e1e83dd"
			"48288c72b424a6287e9ce4e5cc4db0dd67614aecc23b0124a5776d36e5c89483"
		}
	};

	for ( auto test : tests ) {
		int radix = atoi(test[0].c_str());
		Crypto::BigNum A(test[1], radix);
		Crypto::BigNum E(test[2], radix);
		Crypto::BigNum N(test[3], radix);
		Crypto::BigNum X(test[4], radix);
		Crypto::BigNum _RR;

		EXPECT_EQ(_RR, 0);

		for ( std::size_t i = 0 ; i < 2 ; ++i ) {
			Crypto::BigNum Q = A.exp_mod(E, N, &_RR);
			EXPECT_EQ(Q, X);
			EXPECT_NE(_RR, 0);
		}
	}
}

TEST(BigNum, exp_mod_abnormal)
{
	// Even modulus
	{
		std::string exception, expected("Invalid value for modulus");

		try {
			Crypto::BigNum X("23");
			Crypto::BigNum Y("13");
			Crypto::BigNum Z("30");

			Crypto::BigNum A = X.exp_mod(Y, Z);
		} catch ( const Crypto::BigNum::Exception& bne ) {
			exception = bne.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Negative modulus
	{
		std::string exception, expected("Invalid value for modulus");

		try {
			Crypto::BigNum X("23");
			Crypto::BigNum Y("13");
			Crypto::BigNum Z("-29");

			Crypto::BigNum A = X.exp_mod(Y, Z);
		} catch ( const Crypto::BigNum::Exception& bne ) {
			exception = bne.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Negative exponent #1
	{
		std::string exception, expected("Invalid value for exponent");

		try {
			Crypto::BigNum X("23");
			Crypto::BigNum Y("-13");
			Crypto::BigNum Z("29");

			Crypto::BigNum A = X.exp_mod(Y, Z);
		} catch ( const Crypto::BigNum::Exception& bne ) {
			exception = bne.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Negative exponent #2
	{
		std::string exception, expected("Invalid value for exponent");

		try {
			Crypto::BigNum X("-23");
			Crypto::BigNum Y("-13");
			Crypto::BigNum Z("29");

			Crypto::BigNum A = X.exp_mod(Y, Z);
		} catch ( const Crypto::BigNum::Exception& bne ) {
			exception = bne.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(BigNum, signs)
{
	const std::vector<std::vector<std::string>> tests = {
		{  "10",  "10", "-10", "10",  "1" },
		{ "-10", "-10",  "10", "10", "-1" },
		{   "0",   "0",   "0",  "0",  "1" },
		{  "-0",   "0",   "0",  "0",  "1" }
	};

	for ( auto test : tests ) {
		Crypto::BigNum A(test[0]);
		Crypto::BigNum B(test[1]);
		Crypto::BigNum C(test[2]);
		Crypto::BigNum D(test[3]);
		int s = atoi(test[4].c_str());

		EXPECT_EQ(+A,       B);
		EXPECT_EQ(-A,       C);
		EXPECT_EQ(A.abs(),  D);
		if ( A != 0 ) {
			EXPECT_EQ(A.sign(), s);
		}
	}
}

TEST(BigNum, shift_l)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "64", "10", "128", "10", "1" },
		{ 
			"6583855469117335501645160884052389614618802560298345988319720394"
			"6942175511781801365349481443893195731640311168918769144694140678"
			"8869098983929874080332195117465344344350008880118042764943201875"
			"870917468833709791733282363323948005998269792207",
			"10",
			"9048782054863902069192230461972307630540096161011988487272319067"
			"8642804168382367856686134531865643066983017249846286450251272364"
			"3656050227509004394375953550529450359155792165573305054387349553"
			"40526145476988250171181404966718289259743378883640981192704",
			"10",
			"37"
		}
	};

	for ( auto test : tests ) {
		Crypto::BigNum X(test[0], atoi(test[1].c_str()));
		Crypto::BigNum A(test[2], atoi(test[3].c_str()));
		std::size_t shift = (std::size_t)atoi(test[4].c_str());

		X <<= shift;
		EXPECT_EQ(X, A);
	}
}

TEST(BigNum, shift_r)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "128",              "10", "64", "10",   "1" },
		{ "FFFFFFFFFFFFFFFF", "16", "01", "16",  "63" },
		{ "FFFFFFFFFFFFFFFF", "16", "00", "16",  "64" },
		{ "FFFFFFFFFFFFFFFF", "16", "00", "16",  "65" },
		{ "FFFFFFFFFFFFFFFF", "16", "00", "16", "128" },
		{
			"1208155709797014847049069770007605671828714291147120698615890847"
			"0655062657596751678743800859349072277933754739412071824899590036"
			"3209947025063336882559539208430319216688889117222633155838468458"
			"047056355241515415159736436403445579777425189969",
			"10",
			"3433785053053426415343295076376096153094051405637175942660777670"
			"4983799213541577952195782641379856494079816512260299034834332690"
			"9372157800428729167832498229786094773001221702834962899937830963"
			"0601971640587504883789518896817457",
			"10",
			"45"
		}
	};

	for ( auto test : tests ) {
		Crypto::BigNum X(test[0], atoi(test[1].c_str()));
		Crypto::BigNum A(test[2], atoi(test[3].c_str()));
		std::size_t shift = (std::size_t)atoi(test[4].c_str());

		X >>= shift;
		EXPECT_EQ(X, A);
	}
}

TEST(BigNum, bitlen)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "0",  "0" },
		{ "1",  "1" },
		{ "10", "4" },
		{ "15", "4" },
		{ "16", "5" },
		{ "24", "5" },
		{
			"5612568098175228233414189632037248949061396369355639252081601789"
			"2111350604111697682705498319512049040516698827829292076808006940"
			"8739749795845270734810126360163539134623767555567200198311873649"
			"93587901952757307830896531678727717924",
			"764"
	       	}
	};

	for ( auto test : tests ) {
		Crypto::BigNum X(test[0]);
		std::size_t nr_bit = (std::size_t)(atoi(test[1].c_str()));

		EXPECT_EQ(X.bitlen(), nr_bit);
	}
}

TEST(BigNum, lsb)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "24",   "10",  "3" },
		{ "24",   "16",  "2" },
		{ "2000", "16", "13" },
		{
			"5612568098175228233414189632037248949061396369355639252081601789"
			"2111350604111697682705498319512049040516698827829292076808006940"
			"8739749795845270734810126360163539134623767555567200198311873649"
			"93587901952757307830896531678727717924",
			"10",
			"2"
	       	}
	};

	for ( auto test : tests ) {
		Crypto::BigNum X(test[0], atoi(test[1].c_str()));
		std::size_t nr_bit = (std::size_t)(atoi(test[2].c_str()));

		EXPECT_EQ(X.lsb(), nr_bit);
	}
}

TEST(BigNum, get_bit)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "49979687", "25",  "1" },
		{ "49979687", "26",  "0" },
		{ "49979687", "500", "0" },
		{ "49979687", "24",  "0" },
		{ "49979687", "23",  "1" }
	};

	for ( auto test : tests ) {
		Crypto::BigNum X(test[0]);
		int bit = X.get_bit(atoi(test[1].c_str()));

		EXPECT_EQ(bit, atoi(test[2].c_str()));
	}
}

TEST(BigNum, set_bit)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "49979687",         "10", "66756903",                  "10", "24", "1" },
		{ "49979687",         "10", "16425255",                  "10", "25", "0" },
		{ "49979687",         "10", "49979687",                  "10", "80", "0" },
		{ "49979687",         "10", "1208925819614629224685863", "10", "80", "1" },
		{ "FFFFFFFFFFFFFFFF", "16", "FFFFFFFEFFFFFFFF",          "16", "32", "0" },
		{ "00",               "16", "0100000000",                "16", "32", "1" }
	};

	for ( auto test : tests ) {
		Crypto::BigNum X(test[0], atoi(test[1].c_str()));
		Crypto::BigNum Y(test[2], atoi(test[3].c_str()));

		std::size_t pos = (std::size_t)(atoi(test[4].c_str()));
		int val = atoi(test[5].c_str());

		X.set_bit(pos, val);

		EXPECT_EQ(X, Y);
	}
}

TEST(BigNum, gcd)
{
	const std::vector<std::vector<std::string>> tests = {
		{       "693",       "609", "21" },
		{      "1764",       "868", "28" },
		{ "768454923", "542167814",  "1" },
		{
			"4330192409103774782173735729595601098196486470160965605237690108"
			"8117286908333828557375657455739586296509501648386781304366398194"
			"6477698466501451832407592327356331263124555137732393938242285782"
			"144928753919588632679050799198937132922145084847",
			"5781538327977828897150909166778407659250458379645823062042492461"
			"5767585267574909100736280086139775505463827747755708881300297635"
			"7152869957471758322893953596023446423088257361593038497910037910"
			"2915657483866755371559811718767760594919456971354184113721",
			"1"
		}
	};

	for ( auto test : tests ) {
		Crypto::BigNum X(test[0]);
		Crypto::BigNum Y(test[1]);
		Crypto::BigNum A(test[2]);

		EXPECT_EQ(X.gcd(Y), A);
	}
}

TEST(BigNum, lcm)
{
	const std::vector<std::vector<std::string>> tests = {
		{       "693",       "609",              "20097" },
		{      "1764",       "868",              "54684" },
		{ "768454923", "542167814", "416631525760448322" },
		{
			"4330192409103774782173735729595601098196486470160965605237690108"
			"8117286908333828557375657455739586296509501648386781304366398194"
			"6477698466501451832407592327356331263124555137732393938242285782"
			"144928753919588632679050799198937132922145084847",
			"5781538327977828897150909166778407659250458379645823062042492461"
			"5767585267574909100736280086139775505463827747755708881300297635"
			"7152869957471758322893953596023446423088257361593038497910037910"
			"2915657483866755371559811718767760594919456971354184113721",
			"2503517338075212489135871207566367162777047669852556419556493145"
			"1510084346396806255634466197539061957289520775510318596936464359"
			"8515633588811516564098286816069087981946253734550060305103967989"
			"4194362879681248560305113549747501006121511795464193846440485740"
			"8322512032841932666065521282830431757472426235689111717735633391"
			"3787735166702722354199920009995768754045336210090880705313504261"
			"7366595146990190589302604943633086886103537168971491729188489128"
			"524337691056145302843187346207711041885687"
		}
	};

	for ( auto test : tests ) {
		Crypto::BigNum X(test[0]);
		Crypto::BigNum Y(test[1]);
		Crypto::BigNum A(test[2]);

		EXPECT_EQ(X.lcm(Y), A);
	}
}

TEST(BigNum, inv_mod)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "3", "10", "11", "10", "4", "10" },
		{
			"aa4df5cb14b4c31237f98bd1faf527c283c2d0f3eec89718664ba33f9762907c",
			"16",
			"fffbbd660b94412ae61ead9c2906a344116e316a256fd387874c6c675b1d587d",
			"16",
			"8d6a5c1d7adeae3e94b9bcd2c47e0d46e778bc8804a2cc25c02d775dc3d05b0c",
			"16"
		}
	};

	for ( auto test : tests ) {
		Crypto::BigNum X(test[0], atoi(test[1].c_str()));
		Crypto::BigNum Y(test[2], atoi(test[3].c_str()));
		Crypto::BigNum A(test[4], atoi(test[5].c_str()));

		EXPECT_EQ(X.inv(Y), A);
	}
}

TEST(BigNum, inv_mod_abnormal)
{
	// Not inversible
	{
		Crypto::BigNum X("2");
		Crypto::BigNum Y("4");
		Crypto::BigNum Z = X.inv(Y);

		EXPECT_EQ(Z, 0);
	}

	// Modulus is 0
	{
		std::string exception, expected("Invalid value for inverse");

		try {
			Crypto::BigNum X("3");
			Crypto::BigNum Y("0");

			Crypto::BigNum Z = X.inv(Y);
		} catch ( const Crypto::BigNum::Exception& bne ) {
			EXPECT_EQ(bne.what(), expected);
		}
	}

	// Negative modulus
	{
		std::string exception, expected("Invalid value for inverse");

		try {
			Crypto::BigNum X("3");
			Crypto::BigNum Y("-11");

			Crypto::BigNum Z = X.inv(Y);
		} catch ( const Crypto::BigNum::Exception& bne ) {
			exception = bne.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Modulus is 1
	{
		std::string exception, expected("Invalid value for inverse");

		try {
			Crypto::BigNum X("3");
			Crypto::BigNum Y("1");

			Crypto::BigNum Z = X.inv(Y);
		} catch ( const Crypto::BigNum::Exception& bne ) {
			exception = bne.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(BigNum, is_prime)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "0",                                       "false" },
		{ "1",                                       "false" },
		{ "2",                                       "true"  },
		{ "3",                                       "true"  },
		{ "4",                                       "false" },
		{ "5",                                       "true"  },
		{ "27",                                      "false" },
		{ "47",                                      "true"  },
		{ "32452867",                                "true"  },
		{ "49979687",                                "true"  },
		{ "179424691",                               "true"  },
		{ "961748941",                               "true"  },
		{ "2147483647",                              "true"  },
		{ "768614336404564651",                      "true"  },
		{ "2833419889721787128217599",               "true"  },
		{ "195845982777569926302400511",             "true"  },
		{ "4776913109852041418248056622882488319",   "true"  },
		{ "201487636602438195784363",                "true"  },
		{ "845100400152152934331135470251",          "true"  },
		{ "56713727820156410577229101238628035243",  "true"  },
		{ "170141183460469231731687303715884105727", "true"  },
		{
			"8372672888314615197966824332609704928920848298768596527643915716"
			"2337476477581",
			"false"
		}, {
			"8124863741058492145486930848889926709653064363273025820125609258"
			"2281263244641",
			"false"
		}, {
			"8271315072216545639378326866962009955958356944379836588408700365"
			"8612416818696779680911774904743076882582285704243272282809677909"
			"8498192459819306321073968735177531164565305635281198148032612029"
			"767584644305912099",
			"true"
		}, {
			"8271315072216545639378326866962009955958356944379836588408700365"
			"8612416818696779680911774904743076882582285704243272282809677909"
			"8498192459819306321073968735177531164565305635281198148032612029"
			"767584644305912001",
			"false"
		}, {
			"2039568783564019774057658669290345772801939933143482630947726464"
			"5328306272270127763293661606314408817331237288267712387953870940"
			"0158306567338328279154499698366071906766440037074217117805690872"
			"7928481491120222863321448761833763265120835748216479339929612499"
			"17319836219304274280243803104015000563790123",
			"true"
		}, {
			"5318722890542041841850847343751333994083036139821308566452994649"
			"3095217860604584887712914782038799642817556422820478584614120753"
			"2462936339834139412401975338705794646595487324365194792822189473"
			"0922739935805879645716596780844841526038810941769955948133022842"
			"32006001752128168901293560051833646881436219",
			"true"
		}, {
			"3197053047011415391557201372009746646667925260594057925396809749"
			"2946978351282179399561371894317172376523885375243903283598515882"
			"9038528214925658918372196742089464683960239919950882355844766055"
			"3651799376103261276751788573062609555504070444633702398901871897"
			"50909036833976197804646589380690779463976173",
			"true"
		}, {
			"2006038221953246423935162940129175989729674493200749996671034343"
			"7147061600065203657000991202133252778825230090190523657880104468"
			"0456930305350440933538867383130165841118050781326291059830545891"
			"570648243241795871",
			"true"
		}, {
			"8271315072216545639378326866962009955958356944379836588408700365"
			"8612416818696779680911774904743076882582285704243272282809677909"
			"8498192459819306321073968735177531164565305635281198148032612029"
			"767584644305912099",
			"true"
		}, {
			"9642740472484187971450909831571979808550789668822764925727885329"
			"5490411265533843936130621389856951659374426739175403330646512591"
			"9199692703323878557833023573312685002670662846477592597659826113"
			"460619815244721311",
			"true"
		}
	};

	for ( auto test : tests ) {
		Crypto::BigNum X(test[0]);
		bool expected = test[1] == "true";

		EXPECT_EQ(X.is_prime(rnd_std_rand, NULL), expected);
	}
}

TEST(BigNum, is_prime_fail)
{
	// Fail of PRNG at first call
	{
		std::string exception, expected("Random number generator failure");
		int num_fail = 0;
		Crypto::BigNum X("768614336404564651");

		try {
			X.is_prime(rnd_broken, &num_fail);
		} catch ( const Crypto::BigNum::Exception& bne ) {
			exception = bne.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Fail of PRNG at first call
	{
		std::string exception, expected("Random number generator failure");
		int num_fail = 1;
		Crypto::BigNum X("768614336404564651");

		try {
			X.is_prime(rnd_broken, &num_fail);
		} catch ( const Crypto::BigNum::Exception& bne ) {
			exception = bne.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(BigNum, gen_prime)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "3",   "false" },
		{ "128", "false" },
		{ "128", "true"  }
	};

	for ( auto test : tests ) {
		std::size_t bits = (std::size_t)(atoi(test[0].c_str()));
		bool safe        = test[1] == "true";

		Crypto::BigNum X = Crypto::BigNum::gen_prime(bits, rnd_std_rand, NULL, safe);

		std::size_t actual_bits = X.bitlen();

		EXPECT_GE(actual_bits, bits);
		EXPECT_LE(actual_bits, bits + 1);

		EXPECT_TRUE(X.is_prime(rnd_std_rand, NULL));

		if ( safe ) {
			X >>= 1;
			EXPECT_TRUE(X.is_prime(rnd_std_rand, NULL));
		}
	}
}

TEST(BigNum, gen_prime_abnormal)
{
	// Not enough bits requested
	{
		std::string exception, expected("Requested size is not supported");

		try {
			Crypto::BigNum X = Crypto::BigNum::gen_prime(2, rnd_std_rand, NULL);
		} catch ( const Crypto::BigNum::Exception& bne ) {
			exception = bne.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(BigNum, write_string)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "128", "10", "10", "128" },
		{ "128", "10", "16",  "80" },
		{   "0", "10", "10",   "0" },
		{ "-23", "10", "10", "-23" },
		{ "-20", "16", "10", "-32" },
		{ "-23", "16", "16", "-23" },
		{  "29", "10", "15",  "1e" },
		{    "", "16", "16",  "00" },
		{    "", "16", "10",   "0" },
		{
			"5612568098175228233414189632037248949061396369355639252081601789"
			"2111350604111697682705498319512049040516698827829292076808006940"
			"8739749795845270734810126360163539134623767555567200198311873649"
			"93587901952757307830896531678727717924",
			"10",
			"16",
			"0941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290"
			"ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889"
			"af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424"
		}
	};

	for ( auto test : tests ) {
		Crypto::BigNum X(test[0], atoi(test[1].c_str()));

		std::string result = X.to_string(atoi(test[2].c_str()));
		EXPECT_THAT(result, test[3]);
	}
}

TEST(BigNum, write_string_abnormal)
{
	// Invalid character
	{
		std::string exception, expected("Invalid character");

		try {
			Crypto::BigNum X("a28", 10);
		} catch ( const Crypto::BigNum::Exception& bne ) {
			exception = bne.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Invalid radix input
	{
		std::string exception, expected("Radix not supported");

		try {
			Crypto::BigNum X("a28", 19);
		} catch ( const Crypto::BigNum::Exception& bne ) {
			exception = bne.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Invalid radix output
	{
		std::string exception, expected("Radix not supported");
		bool ctor = false;

		try {
			Crypto::BigNum X("-23", 16);
			ctor = true;

			std::string X_str = X.to_string(17);
		} catch ( const Crypto::BigNum::Exception& bne ) {
			exception = bne.what();
		}

		EXPECT_TRUE(ctor);
		EXPECT_EQ(exception, expected);
	}
}

TEST(BigNum, write_binary)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"5612568098175228233414189632037248949061396369355639252081601789"
			"2111350604111697682705498319512049040516698827829292076808006940"
			"8739749795845270734810126360163539134623767555567200198311873649"
			"93587901952757307830896531678727717924",
			"10",
			"0941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290"
			"ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889"
			"af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424"
		}, {
			"123123123123123123123123123",
			"16",
			"0123123123123123123123123123"
		}
	};

	for ( auto test : tests ) {
		int ret;
		uint8_t data[512];
		std::size_t data_sz = sizeof(data);
		std::string str;

		Crypto::BigNum X(test[0], atoi(test[1].c_str()));

		ret = X.to_binary(data, data_sz);
		EXPECT_EQ(ret, 0);

		Crypto::Utils::to_hex(data, data_sz, str, false);
		EXPECT_EQ(str, test[2]);
	}
}

TEST(BigNum, write_binary_abnormal)
{
	int ret;
	std::size_t data_sz;

	Crypto::BigNum X("123123123123123123123123123", 16);

	data_sz = 13;
	ret = X.to_binary(NULL, data_sz);

	EXPECT_EQ(ret, 1);
	EXPECT_EQ(data_sz, (std::size_t)14);
}

TEST(BigNum, self_test)
{
	Crypto::BigNum A, E, N, X, Y, U, V;

	static const std::vector<std::vector<int>> gcd_pairs = {
		{       693,       609, 21 },
		{      1764,       868, 28 },
		{ 768454923, 542167814,  1 }
	};

	A = Crypto::BigNum("EFE021C2645FD1DC586E69184AF4A31E"
			"D5F53E93B5F123FA41680867BA110131"
			"944FE7952E2517337780CB0DB80E61AA"
			"E7C8DDC6C5C6AADEB34EB38A2F40D5E6", 16);

	E = Crypto::BigNum("B2E7EFD37075B9F03FF989C7C5051C20"
			"34D2A323810251127E7BF8625A4F49A5"
			"F3E27F4DA8BD59C47D6DAABA4C8127BD"
			"5B5C25763222FEFCCFC38B832366C29E", 16);

	N = Crypto::BigNum("0066A198186C18C10B2F5ED9B522752A"
			"9830B69916E535C8F047518A889A43A5"
			"94B6BED27A168D31D4A52F88925AA8F5", 16);

	// Test multiplication
	X = A * N;
	U = Crypto::BigNum("602AB7ECA597A3D6B56FF9829A5E8B85"
			"9E857EA95A03512E2BAE7391688D264A"
			"A5663B0341DB9CCFD2C4C5F421FEC814"
			"8001B72E848A38CAE1C65F78E56ABDEF"
			"E12D3C039B8A02D6BE593F0BBBDA56F1"
			"ECF677152EF804370C1A305CAF3B5BF1"
			"30879B56C61DE584A0F53A2447A51E", 16);
	EXPECT_EQ(X, U);

	// Test division
	auto tmp = A.div_mod(N);
	X = tmp.first;
	Y = tmp.second;
	U = Crypto::BigNum("256567336059E52CAE22925474705F39A94", 16);
	V = Crypto::BigNum("6613F26162223DF488E9CD48CC132C7A"
			"0AC93C701B001B092E4E5B9F73BCD27B"
			"9EE50D0657C77F374E903CDFA4C642", 16);
	EXPECT_EQ(X, U);
	EXPECT_EQ(Y, V);

	// Test exponentiation
	X = A.exp_mod(E, N);
	U = Crypto::BigNum("36E139AEA55215609D2816998ED020BB"
			"BD96C37890F65171D948E9BC7CBAA4D9"
			"325D24D6A3C12710F10A09FA08AB87", 16);
	EXPECT_EQ(X, U);

	// Test inversion
	X = A.inv(N);
	U = Crypto::BigNum("003A0AAEDD7E784FC07D8F9EC6E3BFD5"
			"C3DBA76456363A10869622EAC2DD84EC"
			"C5B8A74DAC4D09E03B5E0BE779F2DF61", 16);
	EXPECT_EQ(X, U);

	// Test GCD
	for ( std::size_t i = 0 ; i < gcd_pairs.size() ; ++i ) {
		X = Crypto::BigNum(gcd_pairs[i][0]);
		Y = Crypto::BigNum(gcd_pairs[i][1]);

		A = X.gcd(Y);
		EXPECT_EQ(A, gcd_pairs[i][2]);
	}
}
