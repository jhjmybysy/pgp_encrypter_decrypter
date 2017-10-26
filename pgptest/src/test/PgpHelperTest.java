package test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;

import pgp.PgpHelper;

public class PgpHelperTest {
	// xtransfer 公钥,存放在银行,用于加密
	static final String PUBLIC_KEY_STREAM = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
			+ "Version: GnuPG v2.0.14 (GNU/Linux)\n" + "\n"
			+ "mQENBFnxdmMBCADsOeg2RJfqCmF0PBcD8vsjkVXAOqNf0SCwdN5+NuBA5PyEOeKG\n"
			+ "U3sMY4tALbLtR4oDQOi7smb7/c2gr7FmCb3yZ51UTPhNfrDVjqeadN1CRbtXWQO0\n"
			+ "tZBvScJNfaeApSaGoKs7gNQr9qXVf0qWLyPUsfOO/kSnoJAvs38YezyCZusyulFV\n"
			+ "zCSdC7bNI3+4YzJV0DNterl2ebsbNu5+X3F2TvLQ9awYdo++mLLHfcSeq7kucpHP\n"
			+ "cdHOJGruV2w+/8En/BBYfuu4RU0IVXeTNPrTMIYrx+DC1fMGcj7tG3yj5FMLbvQ7\n"
			+ "FYPBy7vPOzhBrd+xhoanhBm6I18Ovm3gfH/HABEBAAG0KXNpbm8uamlhbyAoc2lu\n"
			+ "bykgPHNpbm8uamlhb0B4dHJhbnNmZXIuY24+iQE4BBMBAgAiBQJZ8XZjAhsDBgsJ\n"
			+ "CAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAKCRB+CVt2mFCB/+97CACujAd07zDg0gjp\n"
			+ "iWFYHQqHRY7vvR/UlLOFvYELWT8JB7ko2kto9w3o9whWJFOMlv9LQPo35SUF98lO\n"
			+ "XZJVvvesVyZJOYqL9x7B2IEY4v+NfGE0pt+FmdtfPrGB9Gfmcj4p9SeXR317vfx6\n"
			+ "tbILjq8Dexv2nhqKGvQZ2SoCJD7CrCusGxCkRJRp4M9HTiIVerZp7SLkd0NJUibZ\n"
			+ "jJU2EK2VzwOiWJKTGumPY9wKLtHCnceH0jMKupCN5NYnLNsz07aAV+FH9DB+Ibe7\n"
			+ "YaicBABXNSU5AZ4NCFezXmv5Q2kFnakYAKU6NUWhtRsU+y7NWwazcaUQxTduH0n2\n"
			+ "AnopTi9UuQENBFnxdmMBCACvGQrDsLVQCHdIHJ0BwIzI+0sIj87XzG31xdfwDbZV\n"
			+ "GZFODflBiUyXV222jgMfMWZ2OGf2EMo6sP60NQH1WdSjHWN4cW5GLGCm3TJDGfq+\n"
			+ "42rboQYoplVO8IaWm4pRNE+KDHF9DcvU3cTOUo0xO3OAUkedrKtu19T6pPCl1KJg\n"
			+ "2ger0kkkH2S6sLFhb0PqMHpfoBRPS/gZBbgyRJNMigeqp654Xs4oIHzrv3gOvj7w\n"
			+ "KSwN3K6EQ8D5w98A1V6Pu/jPGoY7oNb+F3iXZXtvN7fHDS0AFr2WymuaXoPWtOgv\n"
			+ "DmdfGVn3jzBZDsmAq9nAiag0WPEQIBcOpfNHnO+tkG3tABEBAAGJAR8EGAECAAkF\n"
			+ "AlnxdmMCGwwACgkQfglbdphQgf8+9Af+KgjF7Qw/2F+te0YSDbE/M/b/UUFjoQYv\n"
			+ "LhRhqyWEm4Tri+Tt4fdFCUtRSa0j3ULRYNi8IGsAak6YSHEWQhZAsD+ncwKfJS8V\n"
			+ "YJlhyPutQ40XE0iIMszzFYYmHDfGrcH9BPSFXpBP4ObJWyXqHviFT3+XAb2AvU6p\n"
			+ "Or1FtsCRmMLXU/btbT7RjnhLkIhtPERuY6fqeXPB4OL6cW+PEJkrIPZIap9IAz2B\n"
			+ "DPG+m94Vv1wPR8NCU0ruQt2pFysB3ryFNMOlNetHOks0KZFeKBNyAuLnTYff/g7K\n"
			+ "p456H+pRtDDZ16iy6Zyk2snHUhTw6TRF28ifCIqda0s0z68W18HJag==\n" + "=SNZD\n"
			+ "-----END PGP PUBLIC KEY BLOCK-----\n";

	// 银行 私钥,存放在银行,用于签名
	static final String PRIVATE_KEY_STREAM = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
			+ "Version: GnuPG v2.0.14 (GNU/Linux)\n" + "\n"
			+ "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\n"
			+ "pNrJx1IU8Ok0RdvInwiKnWtLNM+vFtfByWo=\n" + "=oFxP\n" + "-----END PGP PRIVATE KEY BLOCK-----\n";
	// 私钥密码
	static final String PASSWORD = "123456";
	static final String PUBLIC_KEY_PATH = "E:\\PGP\\pub.asc";
	static final String PRIVATE_KEY_PATH = "E:\\PGP\\prv.asc";

	// 源文本
	static final String SOURCE_PATH = "E:\\PGP\\aa.txt";
	// 加密后的文本
	static final String ENCRYPTED_PATH = "E:\\PGP\\Encrypted.txt";
	// 解密后的文本
	static final String DECRYPTED_PATH = "E:\\PGP\\Decrypted.txt";

	public static void main(String[] args) throws Exception {
		// 加密 HashAlgorithmTags.MD5
		PgpHelper.doEncrypt(PRIVATE_KEY_STREAM, PASSWORD, PUBLIC_KEY_STREAM, new File(SOURCE_PATH),
				new File(ENCRYPTED_PATH), "MD5");

		// 解密
		FileInputStream pgpIn = new FileInputStream(ENCRYPTED_PATH);
		FileOutputStream plainOut = new FileOutputStream(DECRYPTED_PATH);
		PgpHelper.doDecrypt(PRIVATE_KEY_STREAM, PASSWORD, PUBLIC_KEY_STREAM, pgpIn, plainOut);
	}
}
