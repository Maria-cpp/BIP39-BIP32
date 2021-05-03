#ifndef WORDLIST_H
#define WORDLIST_H

#include <map>
#include <stdexcept>
#include <string>
#include <vector>

class Wordlist
{
   public:
   Wordlist() = default;
   Wordlist(const std::string& filename);

    /** Initialize the wordlist
    * @param language name of the language as string
    * @return true if words count is 2048 else false
     * */
   bool Init(const std::string& language) noexcept;

    /** Gets the language file
    * @param language language name
     * */
   static Wordlist* getLanguage(const char* language) noexcept;
   static Wordlist* english() noexcept;
   static Wordlist* french() noexcept;
   static Wordlist* italian() noexcept;
   static Wordlist* spanish() noexcept;

    /** Gets the word at particular index
    * @param index index is of int type and use to get word against index
    * @return string of word
     * */
   std::string getWord(int index) noexcept;

   std::string language() const noexcept;

   /** Gets the index of the particular word from wordlist
    * @param searchWord word of type string to be searched in a file
    * @returns index of type int
    * */
   int findIndex(const std::string& searchWord);
   bool empty() const noexcept;

   private:
   static std::map<std::string, Wordlist> instances;
   std::vector<std::string> m_words;
   std::string m_language;
   int m_count;
};

#endif    // WORDLIST_H
