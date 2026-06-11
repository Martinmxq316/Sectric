#include <omp.h>
#include "../../Kunlun/crypto/block.hpp"
#include "../../Kunlun/crypto/setup.hpp"
#include "../../Kunlun/mpc/okvs/baxos.hpp"
#include "../../Kunlun/netio/stream_channel.hpp"
extern uint64_t NUM_VERTEX;
extern uint64_t MAX_DEGREE;

extern string file_name;
// extern string table_name = "simple_table_gplus_50000_300.txt";
void saveVectorOfVectorsToFile(const std::vector<std::vector<__m128i>> &data, const std::string &filename)
{
  // std::cout << data.size() << data[0].size() << "!!!!!!!" << std::endl;
  std::ofstream outfile(filename, std::ios::binary);
  if (!outfile.is_open())
  {
    std::cerr << "Failed to open file for writing: " << filename << std::endl;
    return;
  }

  size_t outer_size = data.size();
  outfile.write(reinterpret_cast<const char *>(&outer_size), sizeof(outer_size));
  auto sum = 0;
  for (auto i = 0; i < outer_size; i++)
  {
    auto &inner_vec = data[i];
    size_t inner_size = inner_vec.size();
    sum += inner_size;
    // std::cout<<inner_size<<std::endl;
    outfile.write(reinterpret_cast<const char *>(&inner_size), sizeof(inner_size));
    outfile.write(reinterpret_cast<const char *>(inner_vec.data()), inner_size * sizeof(__m128i));
  }
  // std::cout << sum << std::endl;
  outfile.close();
}

// 从文件中读取 std::vector<std::vector<__m128i>>
std::vector<std::vector<__m128i>> loadVectorOfVectorsFromFile(const std::string &filename)
{
  std::ifstream infile(filename, std::ios::binary);
  if (!infile.is_open())
  {
    std::cerr << "Failed to open file for reading: " << filename << std::endl;
    return {};
  }

  size_t outer_size;
  infile.read(reinterpret_cast<char *>(&outer_size), sizeof(outer_size));
  std::vector<std::vector<__m128i>> data(outer_size);

  for (size_t i = 0; i < outer_size; ++i)
  {
    size_t inner_size;
    infile.read(reinterpret_cast<char *>(&inner_size), sizeof(inner_size));
    // std::cout<<i<<" "<<inner_size<<std::endl;
    data[i].resize(inner_size);
    infile.read(reinterpret_cast<char *>(data[i].data()), inner_size * sizeof(__m128i));
  }

  infile.close();
  return data;
}
void saveVectorToFile(const std::vector<__m128i> &data, const std::string &filename)
{
  std::ofstream outfile(filename, std::ios::binary);
  if (!outfile.is_open())
  {
    std::cerr << "Failed to open file for writing: " << filename << std::endl;
    return;
  }

  size_t size = data.size();
  outfile.write(reinterpret_cast<const char *>(&size), sizeof(size));
  outfile.write(reinterpret_cast<const char *>(data.data()), size * sizeof(__m128i));
  outfile.close();
}

std::vector<__m128i> loadVectorFromFile(const std::string &filename)
{
  std::ifstream infile(filename, std::ios::binary);
  if (!infile.is_open())
  {
    std::cerr << "Failed to open file for reading: " << filename << std::endl;
    return {};
  }

  size_t size;
  infile.read(reinterpret_cast<char *>(&size), sizeof(size));
  std::vector<__m128i> data(size);
  infile.read(reinterpret_cast<char *>(data.data()), size * sizeof(__m128i));
  infile.close();
  return data;
}
inline std::vector<block> u64s_to_blocks(std::vector<uint64_t> &numbers)
{
  auto num_elements = numbers.size();
  std::vector<block> result;
  result.reserve(num_elements);

  for (size_t i = 0; i < num_elements; i++)
  {
    result.push_back(Block::MakeBlock(0, numbers[i]));
  }

  return result;
}
void concatenate_vectors(std::vector<block> &vec1, const std::vector<block> &vec2)
{
  vec1.reserve(vec1.size() + vec2.size());
  vec1.insert(vec1.end(), vec2.begin(), vec2.end());
}
std::vector<block> read_to_block(const std::string &filename)
{
  std::ifstream file(filename);
  if (!file.is_open())
  {
    throw std::runtime_error("Could not open file");
  }

  std::vector<uint64_t> numbers;
  std::string line;
  while (std::getline(file, line))
  {
    uint64_t number = std::stoull(line);
    numbers.push_back(number);
  }

  file.close();

  return u64s_to_blocks(numbers);
}

std::map<uint64_t, std::vector<__m128i>> startServer(uint64_t recvNum, uint64_t size)
{
  int server_fd, new_socket;
  struct sockaddr_in address;
  int opt = 1;
  int addrlen = sizeof(address);
  auto BUFFER_SIZE = size * sizeof(block) + sizeof(int32_t);
  std::vector<char> buffer_vec(BUFFER_SIZE);
  char *buffer = buffer_vec.data();
  std::map<uint64_t, std::vector<__m128i>> client_data_map;

  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
  {
    perror("socket failed");
    exit(EXIT_FAILURE);
  }

  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
  {
    perror("setsockopt");
    close(server_fd);
    exit(EXIT_FAILURE);
  }

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(8999);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
  {
    perror("bind failed");
    close(server_fd);
    exit(EXIT_FAILURE);
  }

  if (listen(server_fd, 100) < 0)
  {
    perror("listen");
    close(server_fd);
    exit(EXIT_FAILURE);
  }
  double MAX = 0;
  while (true)
  {
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
    {
      perror("accept");
      close(server_fd);
      exit(EXIT_FAILURE);
    }

    // Read client_id first
    auto start = std::chrono::steady_clock::now();

    uint32_t client_id_network;
    int valread = read(new_socket, &client_id_network, sizeof(client_id_network));
    int client_id = ntohl(client_id_network); // Convert client_id to host byte order

    // Read the rest of the data into buffer
    int bytesReceived = 0;
    while (bytesReceived < BUFFER_SIZE)
    {
      int bytesRead = read(new_socket, buffer + bytesReceived, BUFFER_SIZE - bytesReceived);
      if (bytesRead <= 0)
      {
        break;
      }
      bytesReceived += bytesRead;
    }

    // Deserialize data from buffer into receivedData vector
    size_t numElements = bytesReceived / sizeof(__m128i);
    std::vector<__m128i> receivedData(numElements);
    std::memcpy(receivedData.data(), buffer, bytesReceived);

    client_data_map[client_id] = receivedData;
    auto end = std::chrono::steady_clock::now();

    // 计算时间间隔
    std::chrono::duration<double> elapsed_seconds = end - start;
    // std::cout << "----" << elapsed_seconds.count() << "s----Received " << receivedData.size() << " __m128i elements from client " << client_id << " " << client_data_map.size() << std::endl;
    if (elapsed_seconds.count() > MAX)
      MAX = elapsed_seconds.count();
    // for (const auto& element : receivedData) {
    //     // print_m128i(element);
    //     // std::cout << std::endl;
    //     Block::PrintBlock(element);
    // }
    close(new_socket);
    if (client_data_map.size() >= recvNum)
      break;
  }
  // std::cout << "=======================" << " receive max time=" << MAX << "s ======================" << std::endl;
  close(server_fd);
  return client_data_map;
}
void serializeVector(const std::vector<__m128i> &data, char *buffer, size_t bufferSize)
{
  size_t dataSize = data.size() * sizeof(__m128i);
  if (dataSize > bufferSize)
  {
    std::cerr << "Buffer size is too small for data serialization" << std::endl;
    return;
  }

  std::memcpy(buffer, data.data(), dataSize);
}

void sendMessage(uint64_t client_id, std::vector<__m128i> data)
{
  int sock = 0;
  struct sockaddr_in serv_addr;

  // Loop until connection is established
  while (true)
  {
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
      std::cerr << "Socket creation error" << std::endl;
      std::this_thread::sleep_for(std::chrono::seconds(1)); // Wait 1 second before retrying
      continue;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8999);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0)
    {
      std::cerr << "Invalid address/ Address not supported" << std::endl;
      std::this_thread::sleep_for(std::chrono::seconds(1)); // Wait 1 second before retrying
      close(sock);
      continue;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
      std::cerr << "Connection failed, retrying..." << std::endl;
      std::this_thread::sleep_for(std::chrono::seconds(1)); // Wait 1 second before retrying
      close(sock);
      continue;
    }

    break; // Connection successful, exit the loop
  }

  // Prepare data to send (example: vector of __m128i)

  // Serialize data into buffer
  char buffer[data.size() * sizeof(__m128i)];
  serializeVector(data, buffer, sizeof(buffer));

  // Send client_id first
  int client_id_network = htonl(client_id); // Convert client_id to network byte order
  send(sock, &client_id_network, sizeof(client_id_network), 0);

  // Send serialized data
  send(sock, buffer, sizeof(buffer), 0);

  // std::cout << "Message sent from client " << client_id << ": " << data.size() << " __m128i elements" << std::endl;
  close(sock);
}
void receive_okvs(uint64_t neighbor_idx, block *data, uint64_t size)
{
  NetIO io("server", "", 9000 + neighbor_idx);
  io.ReceiveBlocks(data, size);
  // std::cout << "recv" << 4000 + neighbor_idx << std::endl;
  // std::unique_ptr<CSocket> sock =
  //     ENCRYPTO::EstablishConnection("127.0.0.1", 9000 + neighbor_idx, SERVER);
  // sock->Receive(data, size * sizeof(block));
  // // std::cout << "end recv" << 4000 + neighbor_idx << std::endl;
  // sock->Close();
  // std::cout << "end close recv" << 4000 + neighbor_idx << std::endl;
}
std::vector<block> flatten(std::vector<std::vector<block>> &vec2D)
{
  // auto num_add = MAX_DEGREE - vec2D.size();
  // for (auto i = 0; i < num_add; i++)
  // {
  //   auto seed = PRG::SetSeed();
  //   auto rand_blocks = PRG::GenRandomBlocks(seed, MAX_DEGREE);
  //   vec2D.emplace_back(rand_blocks);
  // }
  std::vector<block> vec1D;
  for (const auto &row : vec2D)
  {
    vec1D.insert(vec1D.end(), row.begin(), row.end());
  }
  // vec2D.clear();
  // vec2D.shrink_to_fit();
  return vec1D;
}
void preprocess_vertex(uint64_t idx)
{
    // read the data from txt file
    // std::cout << "begin read" << 4000 + idx << std::endl;

    // auto start = std::chrono::steady_clock::now();
    auto neighbors =
        read_to_block(file_name + "neighbor_" +
                        std::to_string(idx) + ".txt");
    uint64_t num_neighbors = neighbors.size();
    auto num_add = std::max(uint64_t(0), MAX_DEGREE - num_neighbors);
    // std::cout << "begin add" << 4000 + idx << std::endl;

    if (num_add > 0)
    {
        auto random_seed = PRG::SetSeed();
        auto add_blocks = PRG::GenRandomBlocks(random_seed, num_add);
        concatenate_vectors(neighbors, add_blocks);
    }

    // std::cout << "Vertex: " << idx << std::endl;
    // Block::PrintBlocks(neighbors);

    auto seed = PRG::SetSeed(fixed_seed, idx);
    std::vector<block> v = PRG::GenRandomBlocks(seed, MAX_DEGREE);

    // std::cout << "Random Blocks of Vertex: " << idx << std::endl;
    // Block::PrintBlocks(v);

    // std::cout << "Vertex " << idx << " key-value pairs" << std::endl;
    // for (uint64_t j = 0; j < neighbors.size(); j++) {
    //     std::cout << "vertex=" << idx << " key=" << ((uint64_t*)(&neighbors[j]))[0] << " value=";
    //     Block::PrintBlock(v[j]);
    // }

    // std::cout << "begin rand" << 4000 + idx << std::endl;
    auto baxos = Baxos<gf_128>(MAX_DEGREE, 1ull << 10, 3);
    std::vector<block> out(baxos.bin_num * baxos.total_size);
    uint8_t thread_num = 8;
    constexpr int kMaxBaxosRetries = 20;
    bool solved = false;
    for (int attempt = 0; attempt < kMaxBaxosRetries && !solved; attempt++)
    {
        try
        {
            auto solve_seed = PRG::SetSeed();
            baxos.solve(neighbors, v, out, &solve_seed, thread_num);
            solved = true;
        }
        catch (const char *e)
        {
            std::cerr << "preprocess_vertex Baxos solve failed for vertex " << idx
                      << ": " << e << ", retry=" << attempt + 1
                      << "/" << kMaxBaxosRetries << std::endl;
        }
        catch (const std::exception &e)
        {
            std::cerr << "preprocess_vertex Baxos solve failed for vertex " << idx
                      << ": " << e.what() << ", retry=" << attempt + 1
                      << "/" << kMaxBaxosRetries << std::endl;
        }
    }
    if (!solved)
    {
        throw std::runtime_error("preprocess_vertex Baxos solve failed after retries");
    }
    // std::cout << "begin send" << 4000 + idx << std::endl;

    // std::cout << "OKVS of Vertex: " << idx << std::endl;
    // Block::PrintBlocks(out);

    // return;

    sendMessage(idx, out);
    // std::unique_ptr<CSocket> sock     auto end = std::chrono::steady_clock::now();

    //   计算时间间隔
    //   auto end = std::chrono::steady_clock::now();
    //   std::chrono::duration<double> elapsed_seconds = end - start;
    //   if (idx == 0)
    //     std::cout <<std::endl<< "!!!!!!!!!!!!" << elapsed_seconds.count() << "!!!!!!!!!!!!!!!!!!!!!" << std::endl;
    
    // // std::cout << "send" << 4000 + idx << std::endl;
    // sock->Send(out.data(), out.size() * sizeof(block));
    // // std::cout << "end send" << 4000 + idx << std::endl;
    // sock->Close();
    // std::cout << "end close send" << 4000 + idx << std::endl;
}
std::vector<std::vector<block>> neighbor_request(uint64_t idx, std::vector<block> &neighbors)
{
    // read the data from txt file

    auto baxos = Baxos<gf_128>(MAX_DEGREE, 1ull << 10, 3);
    auto size = baxos.bin_num * baxos.total_size;

    std::vector<std::vector<block>> neighbor_okvs(NUM_VERTEX, std::vector<block>(size));
    std::vector<std::vector<block>> neighbor_of_neighbor(NUM_VERTEX,
                                                        std::vector<block>(MAX_DEGREE));
    // std::cout << "Sleeping for 4 seconds..." << std::endl;
    // std::cout << neighbors.size() << std::endl;
    // Get the maximum number of threads supported by the system
    // int max_threads = omp_get_max_threads();

    // Set the number of threads to the maximum number of threads
    // omp_set_num_threads(max_threads);

    auto clientData = startServer(NUM_VERTEX - 1, size);

    // std::cout << "Finish receiving OKVS.\nNUM_VERTEX: " << NUM_VERTEX << std::endl;

    
    // #pragma omp parallel for
    for (auto i = 0; i < NUM_VERTEX; i++)
    {
        // receive_okvs(((uint64_t*)&neighbors[i])[0], neighbor_okvs[i].data(), size);
        // neighbor_okvs[i] = clientData[((uint64_t *)(&neighbors[i]))[0]];
        if (i == idx) continue;
        neighbor_okvs[i] = clientData[i];
        // std::cout << "Vertex " << i << std::endl;
        // Block::PrintBlocks(neighbor_okvs[i]);
    }

    // return std::vector<block>();

    // std::cout << "begin decoding" << neighbors.size() << std::endl;

    for (auto i = 0; i < NUM_VERTEX; i++)
    {
        // std::cout << i << neighbor_okvs[i].size() << std::endl;
        if (i == idx) continue;
        auto seed_ = PRG::SetSeed();
        neighbor_of_neighbor[i] = PRG::GenRandomBlocks(seed_, MAX_DEGREE);
        baxos.decode(neighbors, neighbor_of_neighbor[i], neighbor_okvs[i], 8);
        // std::cout << "Vertex " << i << std::endl;
        // Block::PrintBlocks(neighbor_of_neighbor[i]);
        // std::cout << "Decode OKVS of vertex " << i << std::endl;
        // for (uint64_t k = 0; k < neighbors.size(); k++) {
        //     std::cout << "query_key=" << ((uint64_t*)(&neighbors[k]))[0] << " value=";
        //     Block::PrintBlock(neighbor_of_neighbor[i][k]);
        // }
    }
    // std::cout << "begin return" << std::endl;
    return neighbor_of_neighbor;
    // Block::PrintBlocks(flatten(neighbor_of_neighbor));
    // return flatten(neighbor_of_neighbor);
}
auto test_request(uint64_t role, uint64_t test_target, uint64_t vertex_idx,
                  std::vector<block> neighbors)
{
    auto _max = std::numeric_limits<uint64_t>::max();
    if (test_target != _max && role == 1) // Querier
    {
      // return std::vector<block>();
      auto ans1 = neighbor_request(test_target, neighbors);
      // std::cout<<"begin ans1:"<<std::endl;
      return ans1;
      // return std::vector<block>();
    }
    if (vertex_idx != _max && role == 2) // other vertices send OKVS to Querier
    {
      preprocess_vertex(vertex_idx);
      // std::cout<<"begin ans2:"<<std::endl;
      // return std::vector<block>();
      return std::vector<std::vector<block>>();
    }
    if (test_target != _max && role == 0) // Server
    {
      // return std::vector<block>();
      // std::vector<block> randoms;
      // std::cout<<"begin random:"<<std::endl;
      std::vector<std::vector<block>> randoms(NUM_VERTEX, std::vector<block>(MAX_DEGREE));
      // randoms.reserve(NUM_VERTEX * MAX_DEGREE);
      for (auto i = 0; i < NUM_VERTEX; i++)
      {
        if (i == test_target) continue;
        auto seed_ = PRG::SetSeed(fixed_seed, i);
        auto tmp_vec = PRG::GenRandomBlocks(seed_, MAX_DEGREE);
        // std::copy(tmp_vec.begin(), tmp_vec.end(), std::back_inserter(randoms));
        randoms[i] = tmp_vec;
        // std::cout << "Server's random numbers for vertex " << i << std::endl;
        // Block::PrintBlocks(randoms[i]);
      }
      return randoms;
    }
}
