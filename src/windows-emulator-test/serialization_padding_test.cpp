#include <gtest/gtest.h>

#include <memory_manager.hpp>

#include <cstddef>
#include <cstring>
#include <vector>

namespace sogen::test
{
    namespace
    {
        using region_type = basic_memory_region<nt_memory_permission>;

        std::vector<region_type> make_regions(const int padding_fill)
        {
            std::vector<region_type> regions(2);
            for (auto& region : regions)
            {
                std::memset(static_cast<void*>(&region), padding_fill, sizeof(region));
            }

            regions[0].start = 0x10000;
            regions[0].length = 0x1000;
            regions[0].permissions = memory_permission::read_write;
            regions[1].start = 0x11000;
            regions[1].length = 0x3000;
            regions[1].permissions = nt_memory_permission{memory_permission::read, memory_permission_ext::guard};
            return regions;
        }
    }

    TEST(SerializationPaddingTest, ZeroPaddedVectorsKeepTheVectorLayoutWithoutHostBytes)
    {
        const auto regions = make_regions(0xCC);

        utils::buffer_serializer serializer{};
        serializer.write_zero_padded_vector(regions, &region_type::start, &region_type::length, &region_type::permissions);

        const auto zeroed = make_regions(0);
        utils::buffer_serializer expected{};
        expected.write(static_cast<uint64_t>(zeroed.size()));
        expected.write(zeroed.data(), zeroed.size() * sizeof(region_type));

        EXPECT_EQ(expected.get_buffer(), serializer.get_buffer());

        utils::buffer_deserializer deserializer{serializer.get_buffer()};
        const auto read = deserializer.read_vector<region_type>();
        ASSERT_EQ(regions.size(), read.size());
        for (size_t i = 0; i < regions.size(); ++i)
        {
            EXPECT_EQ(regions[i].start, read[i].start);
            EXPECT_EQ(regions[i].length, read[i].length);
            EXPECT_EQ(regions[i].permissions, read[i].permissions);
        }
    }
}
