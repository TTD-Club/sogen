#include <gtest/gtest.h>

#include <fstream>

#include <file_system.hpp>

namespace sogen::test
{
    TEST(FileSystemTest, PathTraversalIsNotPossible)
    {
        const auto current_dir = std::filesystem::current_path();

        const file_system fs{current_dir};

        EXPECT_EQ(current_dir / "a", fs.translate(windows_path('a', {u"..", u"..", u"..", u"..", u"a.txt"})));
        EXPECT_EQ(current_dir / "a", fs.translate(windows_path('a', {u"b", u"..", u"..", u"b", u"..", u"a.txt"})));
        EXPECT_EQ(current_dir / "a", fs.translate(windows_path('a', {u"..", u"b"})));
    }

    TEST(FileSystemTest, DirectoryMappingMountsSubtree)
    {
        const auto current_dir = std::filesystem::current_path();

        file_system fs{current_dir};
        fs.map(windows_path('c', {u"mnt"}), current_dir);

        // A file under the mounted directory resolves to the same file under the host directory.
        EXPECT_EQ(current_dir / "sub" / "a.txt", fs.translate(windows_path('c', {u"mnt", u"sub", u"a.txt"})));

        // ".." cannot escape the mount; it is confined to the mounted directory.
        EXPECT_EQ(current_dir, fs.translate(windows_path('c', {u"mnt", u"..", u"..", u"etc"})));

        // The deepest matching mount wins.
        fs.map(windows_path('c', {u"mnt", u"deep"}), current_dir / "other");
        EXPECT_EQ(current_dir / "other" / "x.txt", fs.translate(windows_path('c', {u"mnt", u"deep", u"x.txt"})));

        // An exact file mapping still takes precedence over the directory mount.
        fs.map(windows_path('c', {u"mnt", u"exact.txt"}), current_dir / "elsewhere.txt");
        EXPECT_EQ(current_dir / "elsewhere.txt", fs.translate(windows_path('c', {u"mnt", u"exact.txt"})));
    }

    // Guest names ignore case: entries the host keeps in another case are found, and new entries take the guest's case.
    TEST(FileSystemTest, NamesKeepTheirCase)
    {
        const auto root =
            std::filesystem::temp_directory_path() / ("sogen-case-" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()));
        std::filesystem::remove_all(root);
        std::filesystem::create_directories(root / "c" / "MixedDir");
        std::ofstream(root / "c" / "MixedDir" / "File.TXT").put('x');

        const file_system fs{root};
        const auto found = fs.translate(windows_path('c', {u"mixeddir", u"file.txt"}));
        EXPECT_TRUE(std::filesystem::exists(found));
        EXPECT_EQ(std::filesystem::canonical(found).filename(), "File.TXT");
        EXPECT_EQ(fs.true_case(u"C:\\MIXEDDIR\\FILE.txt"), u"\\MixedDir\\File.TXT");

        const auto created = fs.translate_for_creation(windows_path('c', {u"mixeddir", u"newname.txt"}), u"C:\\mixeddir\\NewName.txt");
        EXPECT_EQ(created.filename(), "NewName.txt");
        EXPECT_TRUE(std::filesystem::equivalent(created.parent_path(), root / "c" / "MixedDir"));

        // An existing entry keeps its name, unless a rename changes only its case.
        const auto existing = fs.translate_for_creation(windows_path('c', {u"mixeddir", u"file.txt"}), u"C:\\mixeddir\\FILE.txt");
        EXPECT_TRUE(std::filesystem::equivalent(existing, root / "c" / "MixedDir" / "File.TXT"));
        const auto renamed = fs.translate_for_creation(windows_path('c', {u"mixeddir", u"file.txt"}), u"C:\\mixeddir\\FILE.txt", true);
        EXPECT_EQ(renamed.filename(), "FILE.txt");

        std::filesystem::remove_all(root);
    }
} // namespace sogen::test
