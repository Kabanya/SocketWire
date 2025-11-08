#ifndef BITSTREAM_H
#define BITSTREAM_H

#include <vector>
#include <cstdint>
#include <type_traits>
#include <string>

namespace socketwire
{

class BitStream
{
private:
  std::vector<std::uint8_t> buffer;
  size_t m_WritePose = 0;
  size_t m_ReadPose = 0;

public:
  BitStream();
  BitStream(const std::uint8_t* data, size_t size);

  ///@name Побитовые операции
  ///@{
  /**
   * @brief Записывает один бит в поток
   * @param value Значение бита для записи
   */
  void writeBit(bool value);
  /**
   * @brief Читает один бит из потока
   * @return Значение прочитанного бита
   */
  bool readBit();
  ///@}

  /**
   * @brief Записывает указанное количество бит в поток
   * @param value Значение для записи
   * @param bitCount Количество бит для записи
   */
  void writeBits(uint32_t value, uint8_t bit_count);
  /**
   * @brief Читает указанное количество бит из потока
   * @param bitCount Количество бит для чтения
   * @return Значение прочитанных бит
   */
  uint32_t readBits(uint8_t bit_count);

  ///@name Операции с байтами
  ///@{
  /**
   * @brief Записывает массив байт в поток
   * @param data Указатель на данные для записи
   * @param size Размер данных в байтах
   */
  void writeBytes(const void* data, size_t size);
  /**
   * @brief Читает массив байт из потока
   * @param data Указатель для записи прочитанных данных
   * @param size Размер данных в байтах для чтения
   */
  void readBytes(void* data, size_t size);
  ///@}

  ///@name Операции выравнивания
  ///@{
  /**
   * @brief Выравнивает указатель записи на границу байта
   */
  void alignWrite();
  /**
   * @brief Выравнивает указатель чтения на границу байта
   */
  void alignRead();
  ///@}

  /// @name Операции с template
  /// @{
  /**
   * @brief Записывает значение в поток
   * @tparam T Тип значения (должен быть тривиально копируемым)
   * @param value Значение для записи
   */
  template<typename T>
  void write(const T& value)
  {
    static_assert(std::is_trivially_copyable_v<T>, "Type must be trivially copyable");
    writeBytes(&value, sizeof(T));
  }

  /**
   * @brief Читает значение из потока
   * @tparam T Тип значения (должен быть тривиально копируемым)
   * @param value Ссылка для записи прочитанного значения
   */
  template<typename T>
  void read(T& value)
  {
    static_assert(std::is_trivially_copyable_v<T>, "Type must be trivially copyable");
    readBytes(&value, sizeof(T));
  }
  ///@}

  /**
   * Специализация шаблона для записи строки
   * @brief Записывает строку в поток
   * @param value Строка для записи
   */
  void write(const std::string& value);
  /**
   * Специализация шаблона для чтения строки
   * @brief Читает строку из потока
   * @param value Ссылка для записи прочитанной строки
   */
  void read(std::string& value);

  ///@name Операции с массивами булевых значений
  ///@{
  /**
   * @brief Записывает массив булевых значений в поток
   * @param bools Вектор булевых значений для записи
   */
  void writeBoolArray(const std::vector<bool>& bools);
  /**
   * @brief Читает массив булевых значений из потока
   * @return Вектор прочитанных булевых значений
   */
  std::vector<bool> readBoolArray();
  ///@}

  /// @name Полезные методы
  /// @{
  /**
   * @brief Возвращает указатель на данные в потоке
   * @return Указатель на данные в потоке
   */
  const std::uint8_t* getData() const;
  /**
   * @brief Возвращает размер данных в потоке в байтах
   * @return Размер данных в потоке в байтах
   */
  size_t getSizeBytes() const;
  /**
   * @brief Возвращает размер данных в потоке в битах
   * @return Размер данных в потоке в битах
   */
  size_t getSizeBits() const;
  /**
   * @brief Сбрасывает указатель записи в начало потока
   */
  void resetWrite();
  /**
   * @brief Сбрасывает указатель чтения в начало потока
   */
  void resetRead();
  /**
   * @brief Очищает поток
   */
  void clear();
  ///@}

  void writeQuantizedFloat(float value, float min, float max, uint8_t bits);
  float readQuantizedFloat(float min, float max, uint8_t bits);
};

} // namespace socketwire

#endif // BITSTREAM_H