import java.io.File
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

object AesCrypto {
    private val key: SecretKeySpec
    private const val ALGORITHM = "AES/ECB/PKCS5Padding"

    init {
        val charPool = ('a'..'z') + ('A'..'Z')
        val randomString = (1..8).map { Random.nextInt(0, charPool.size).let { charPool[it] } }.joinToString { "" }
        val hashedKey = MessageDigest.getInstance("SHA-256").digest(randomString.encodeToByteArray())
        key = SecretKeySpec(hashedKey, "AES")
    }

    fun encrypt(content: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.doFinal(content)
    }
}

fun main(args: Array<String>) {
    val (command, filePath) = args

    val file = File(filePath)
    val bytes = file.readBytes()

    when (command) {
        "prepare" -> prepare(bytes, file.extension)
        "encode" -> encode(bytes, file.extension)
        "translate" -> translate(bytes, file.extension)
        "decode" -> decode(bytes, file.extension)
        else -> throw Error("unknown command")
    }
}

fun prepare(content: ByteArray, extension: String) {
    val dict = ByteArray(256 * 16)
    val writeData = ByteArray(content.size * 16)

    for (i in (0..255)) {
        dict[i*16] = i.toByte()
        for (j in (i*16 + 1..<i*16 + 15)) {
            dict[j] = 0
        }
    }

    for (i in content.indices) {
        writeData[i*16] = content[i]
        for (j in (i*16 + 1..i*16 + 15)) {
            writeData[j] = 0
        }
    }

    val merged = dict + writeData
    File("prepared.$extension").writeBytes(merged)
}

fun encode(content: ByteArray, extension: String) {
    val encrypted = AesCrypto.encrypt(content)
    File("encrypted.$extension").writeBytes(encrypted)
}

fun translate(content: ByteArray, extension: String) {
    val dict = content.slice(0..<4096).chunked(16)
    val map = linkedMapOf<Byte,List<Byte>>()
    var text = ""
    for (i in dict.indices) {
        text += "[${i},0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] >>>>> ${dict[i]}" + "\r\n"
        map[i.toByte()] = dict[i]
    }
    text = text.dropLast(2)
    File("map.txt").writeText(text)
}

fun decode(content: ByteArray, extension: String) {
    val dict = content.slice(0..<4096).chunked(16)
    val map = linkedMapOf<Byte,List<Byte>>()
    for (i in dict.indices) {
        map[i.toByte()] = dict[i]
    }
    val toDecode = content.slice(4096..<content.size).chunked(16)
    val result = mutableListOf<Byte>()
    for (chunk in toDecode) {
        for (entry in map) {
            if (chunk == entry.value) {
                result.add(entry.key)
            }
        }
    }
    File("decrypted.$extension").writeBytes(result.toByteArray())
}