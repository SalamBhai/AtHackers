using AtHackers.Exceptions;
using AtHackers.Hashers;
namespace AtHackers.Unifier
{
    public class AtHackerHashProvider
    {

        public static string GenerateHash(string PasswordToHash, string HashAlgorithm = "BCRYPT",
         bool OnlyHashRequired = false, bool IsEnhancedBCrypt = true)
        {
            var hash = "";
            #region  GenerateHash
            switch (HashAlgorithm.ToLower())
            {
                case "sha256":
                    hash = new SHA256HASHER().GenerateHash(PasswordToHash, OnlyHashRequired);
                    break;
                case "sha384":
                    hash = new SHA384HASHER().GenerateHash(PasswordToHash, OnlyHashRequired);
                    break;
                case "sha512":
                    hash = new SHA512HASHER().GenerateHash(PasswordToHash, OnlyHashRequired);
                    break;
                case "bcrypt":
                    hash = BCRYPTHASHER.GenerateHash(PasswordToHash, IsEnhancedBCrypt);
                    break;
                case "":
                    throw new ValueCannotBeNullException();

                default:
                    hash = BCRYPTHASHER.GenerateHash(PasswordToHash, IsEnhancedBCrypt);
                    break;
            }
            #endregion  GenerateHash
            return hash;
        }
        /// <summary>
        /// Enhanced secure hashing algorithm that mixes multi iterations and multi algorithm 
        /// types to create a more secure algorithm that should be more secure than a standard
        /// Shw256 Hash that can be easily hacked using a table / dictionary lookup attacks.
        /// </summary>
        /// <param name="hashedPassword"> The Stored Hashed Password</param>
        /// <param name="plainInput"> The Plain Input Used For Storing The Password Hash</param>
        /// <param name="HashAlgorithm"> The Hash Algorithm For The Geneartion Of The Hash</param>
        /// <returns>Bool: <see langword="true"/>  Or <see langword="false"/> for passwordhash and its plain text equivalent</returns>

        public static bool ValidatePassword(string plainInput, string hashedPassword,
         string HashAlgorithm = "BCRYPT", bool IsEnhancedBCrypt = true)
        {
            var passwordStatus = false;
            #region ValidatePassword 
            switch (HashAlgorithm.ToLower())
            {
                case "sha256":
                    passwordStatus = new SHA256HASHER().ValidatePassword(plainInput, hashedPassword);
                    break;
                case "sha384":
                    passwordStatus = new SHA384HASHER().ValidatePassword(plainInput, hashedPassword);
                    break;
                case "sha512":
                    passwordStatus = new SHA512HASHER().ValidatePassword(plainInput, hashedPassword);
                    break;
                case "bcrypt":
                    passwordStatus = BCRYPTHASHER.ValidatePassword(plainInput, hashedPassword, IsEnhancedBCrypt);
                    break;
                case null:
                    throw new ValueCannotBeNullException();
                default:
                    passwordStatus = BCRYPTHASHER.ValidatePassword(plainInput, hashedPassword, IsEnhancedBCrypt);
                    break;
            }
            #endregion ValidatePassword
            return passwordStatus;
        }
    }
}