-- phpMyAdmin SQL Dump
-- version 5.1.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Jan 18, 2022 at 05:00 AM
-- Server version: 10.4.21-MariaDB
-- PHP Version: 8.0.11

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `library_db`
--

-- --------------------------------------------------------

--
-- Table structure for table `books`
--

CREATE TABLE `books` (
  `book_id` int(11) NOT NULL,
  `category_id` int(11) NOT NULL,
  `book` varchar(100) COLLATE utf16_turkish_ci NOT NULL,
  `author` varchar(50) COLLATE utf16_turkish_ci NOT NULL,
  `ISBN` bigint(20) NOT NULL,
  `is_issued` tinyint(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf16 COLLATE=utf16_turkish_ci;

--
-- Dumping data for table `books`
--

INSERT INTO `books` (`book_id`, `category_id`, `book`, `author`, `ISBN`, `is_issued`) VALUES
(1, 9, 'Dune', 'Frank Herbert', 4832951841, 1),
(2, 9, 'I, Robot', 'Isaac Asimov', 2356324563, 1),
(3, 9, 'Neuromancer', 'William Gibson', 2384235235, 1),
(5, 9, 'Do Androids Dream of Electric Sheep?', 'Philip K. Dick', 5475675745, 1),
(6, 9, 'No way home', 'Stan lee', 4543535353, 1),
(8, 3, 'three men in a boat', 'ruskin bond', 3345678901, 1);

-- --------------------------------------------------------

--
-- Table structure for table `categories`
--

CREATE TABLE `categories` (
  `category_id` int(11) NOT NULL,
  `category` varchar(50) COLLATE utf16_turkish_ci NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf16 COLLATE=utf16_turkish_ci;

--
-- Dumping data for table `categories`
--

INSERT INTO `categories` (`category_id`, `category`) VALUES
(1, 'Horror'),
(2, 'Science'),
(3, 'Novel'),
(4, 'Poetry'),
(5, 'Biography'),
(6, 'History'),
(7, 'Philosophy'),
(8, 'Art'),
(9, 'Sci-fi'),
(10, 'Fantasy'),
(11, 'Romance'),
(12, 'Children\'s'),
(13, 'Crime'),
(14, 'Drama'),
(15, 'Graphic novel');

-- --------------------------------------------------------

--
-- Table structure for table `loaned_books`
--

CREATE TABLE `loaned_books` (
  `transaction_id` int(11) NOT NULL,
  `book_id` int(11) NOT NULL,
  `personnel_id` int(11) NOT NULL,
  `member_id` int(11) NOT NULL,
  `date_of_issue` varchar(50) COLLATE utf16_turkish_ci NOT NULL,
  `date_of_return` varchar(50) COLLATE utf16_turkish_ci NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf16 COLLATE=utf16_turkish_ci;

--
-- Dumping data for table `loaned_books`
--

INSERT INTO `loaned_books` (`transaction_id`, `book_id`, `personnel_id`, `member_id`, `date_of_issue`, `date_of_return`) VALUES
(1, 5, 1000, 1000, '11.12.2019 22:37', ''),
(2, 2, 1000, 1000, '11.12.2019 22:37', ''),
(3, 3, 1000, 1001, '13.01.2022 13:43', ''),
(4, 1, 1000, 1001, '13.01.2022 13:44', ''),
(6, 6, 1000, 1001, '17.01.2022 5:38', ''),
(11, 8, 1000, 1006, '18.01.2022 4:27', '');

-- --------------------------------------------------------

--
-- Table structure for table `members`
--

CREATE TABLE `members` (
  `member_id` int(11) NOT NULL,
  `member_name` varchar(50) COLLATE utf16_turkish_ci NOT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf16 COLLATE=utf16_turkish_ci;

--
-- Dumping data for table `members`
--

INSERT INTO `members` (`member_id`, `member_name`, `is_active`) VALUES
(1000, 'abcd', 1),
(1001, 'Noor', 1),
(1002, 'Roshan', 1),
(1003, 'Ayush Legend', 0),
(1004, 'tony stark', 0),
(1005, 'steve rogers', 0),
(1006, 'ram', 1);

-- --------------------------------------------------------

--
-- Table structure for table `personnel`
--

CREATE TABLE `personnel` (
  `personnel_id` int(11) NOT NULL,
  `personnel_login` varchar(50) COLLATE utf16_turkish_ci NOT NULL,
  `personnel_password` varchar(50) COLLATE utf16_turkish_ci NOT NULL,
  `email` varchar(40) COLLATE utf16_turkish_ci NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf16 COLLATE=utf16_turkish_ci;

--
-- Dumping data for table `personnel`
--

INSERT INTO `personnel` (`personnel_id`, `personnel_login`, `personnel_password`, `email`) VALUES
(1000, 'admin', 'xyz', 'dnoorali2015@gmail.com');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `books`
--
ALTER TABLE `books`
  ADD PRIMARY KEY (`book_id`),
  ADD KEY `category_id` (`category_id`);

--
-- Indexes for table `categories`
--
ALTER TABLE `categories`
  ADD PRIMARY KEY (`category_id`);

--
-- Indexes for table `loaned_books`
--
ALTER TABLE `loaned_books`
  ADD PRIMARY KEY (`transaction_id`),
  ADD KEY `loaned_books_ibfk_1` (`book_id`),
  ADD KEY `loaned_books_ibfk_2` (`member_id`),
  ADD KEY `loaned_books_ibfk_3` (`personnel_id`);

--
-- Indexes for table `members`
--
ALTER TABLE `members`
  ADD PRIMARY KEY (`member_id`);

--
-- Indexes for table `personnel`
--
ALTER TABLE `personnel`
  ADD PRIMARY KEY (`personnel_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `books`
--
ALTER TABLE `books`
  MODIFY `book_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;

--
-- AUTO_INCREMENT for table `categories`
--
ALTER TABLE `categories`
  MODIFY `category_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=16;

--
-- AUTO_INCREMENT for table `loaned_books`
--
ALTER TABLE `loaned_books`
  MODIFY `transaction_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=12;

--
-- AUTO_INCREMENT for table `members`
--
ALTER TABLE `members`
  MODIFY `member_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=1007;

--
-- AUTO_INCREMENT for table `personnel`
--
ALTER TABLE `personnel`
  MODIFY `personnel_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=1001;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `books`
--
ALTER TABLE `books`
  ADD CONSTRAINT `books_ibfk_1` FOREIGN KEY (`category_id`) REFERENCES `categories` (`category_id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `loaned_books`
--
ALTER TABLE `loaned_books`
  ADD CONSTRAINT `loaned_books_ibfk_1` FOREIGN KEY (`book_id`) REFERENCES `books` (`book_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `loaned_books_ibfk_2` FOREIGN KEY (`member_id`) REFERENCES `members` (`member_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `loaned_books_ibfk_3` FOREIGN KEY (`personnel_id`) REFERENCES `personnel` (`personnel_id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
