import * as crypto from "../index";

////////////////////////////////////////////////////
/// Crypto tests : http://nodejs.org/api/crypto.html
////////////////////////////////////////////////////

var hmacResult: string = crypto.createHmac('md5', 'hello').update('world').digest('hex');

function crypto_cipher_decipher_string_test() {
	var key:Buffer = new Buffer([1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6, 7]);
	var clearText:string = "This is the clear text.";
	var cipher:crypto.Cipher = crypto.createCipher("aes-128-ecb", key);
	var cipherText:string = cipher.update(clearText, "utf8", "hex");
	cipherText += cipher.final("hex");

	var decipher:crypto.Decipher = crypto.createDecipher("aes-128-ecb", key);
	var clearText2:string = decipher.update(cipherText, "hex", "utf8");
	clearText2 += decipher.final("utf8");

	assert.equal(clearText2, clearText);
}

function crypto_cipher_decipher_buffer_test() {
	var key:Buffer = new Buffer([1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6, 7]);
	var clearText:Buffer = new Buffer([1, 2, 3, 4, 5, 6, 7, 8, 9, 8, 7, 6, 5, 4]);
	var cipher:crypto.Cipher = crypto.createCipher("aes-128-ecb", key);
	var cipherBuffers:Buffer[] = [];
	cipherBuffers.push(cipher.update(clearText));
	cipherBuffers.push(cipher.final());

	var cipherText:Buffer = Buffer.concat(cipherBuffers);

	var decipher:crypto.Decipher = crypto.createDecipher("aes-128-ecb", key);
	var decipherBuffers:Buffer[] = [];
	decipherBuffers.push(decipher.update(cipherText));
	decipherBuffers.push(decipher.final());

	var clearText2:Buffer = Buffer.concat(decipherBuffers);

	assert.deepEqual(clearText2, clearText);
}
