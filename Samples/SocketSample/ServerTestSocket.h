#ifndef SERVER_TEST_SOCKET_H
#define SERVER_TEST_SOCKET_H

#include <arpa/inet.h>
#include <string>
#include <queue>


struct Client
{
  sockaddr_in addr;
  std::string id;
};

struct MathProblem
{
  std::string problem;
  int answer;
};

struct MathDuel
{
  Client challenger;
  Client opponent;
  int answer;
  std::string problem;
  bool active;
  bool solved;
};

extern std::queue<Client> duelQueue;
extern std::vector<MathDuel> activeDuels;

//Msg & input logic
std::string client_to_string(const Client& client);
void msg_to_all_clients(int sfd, const std::vector<Client>& clients, const std::string& message);
void msg_to_client(int sfd, const Client& client, const std::string& message);
void msg_to_server_and_all(std::string &message, Client &currentClient, int sfd, std::vector<Client> &clients, char buffer[1000]);

//MATH logic
MathProblem generate_math_problem();
void start_math_duel(int sfd, const Client& challenger, const Client& opponent, std::vector<Client>& all_clients);
bool is_in_duel(const Client& client, MathDuel** current_duel = nullptr);
void server_input_processing(int sfd, std::vector<Client>& clients);
void mathduel(std::string message, Client currentClient, int sfd, std::vector<Client> &clients);

#endif // SERVER_TEST_SOCKET_H