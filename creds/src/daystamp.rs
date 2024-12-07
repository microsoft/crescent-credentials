// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use chrono::{DateTime, Datelike, Local};

// The function ymd_to_ordinal() and supporting functions are ported from 
//    https://github.com/python/cpython/blob/54b5e4da8a4c6ae527ab238fcd6b9ba0a3ed0fc7/Lib/datetime.py#L63

// usize::MAX is a placeholder for indexing purposes.
const DAYS_IN_MONTH: [usize; 13] = [usize::MAX, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
const DAYS_BEFORE_MONTH : [usize; 13] = [usize::MAX, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
// Returns 1 if leap year, 0 otherwise.
fn is_leap(year: usize) -> bool {
    (year % 4 == 0) && ((year % 100 != 0) || (year % 400 == 0))
}
// Returns the number of days that came before the given year (from year 0)
fn days_before_year(year: usize) -> usize {
    let y = year - 1;
    y*365 + y/4 + y/100 + y/400
}
// Returns the number of days in that month in that year.
fn days_in_month(year: usize, month: usize) -> usize {
    assert!((1..=12).contains(&month));
    if month == 2 && is_leap(year) {
        return 29;
    }
    DAYS_IN_MONTH[month]
}
// Returns the number of days in the year preceding the first day of the given month.
fn days_before_month(year: usize, month: usize) -> usize {
    assert!((1..=12).contains(&month), "month must be in 1..12");
    let extra_day = if month > 2 && is_leap(year) { 1 } else { 0 };
    DAYS_BEFORE_MONTH[month] + extra_day
}
// Converts year, month, day to ordinal, considering 01-Jan-0001 as day 1.
fn ymd_to_ordinal(year: usize, month: usize, day: usize) -> usize {
    assert!((1..=12).contains(&month), "month must be in 1..12");
    let dim = days_in_month(year, month);
    assert!(1 <= day && day <= dim, "day must be in 1..{}", dim);
    days_before_year(year) + days_before_month(year, month) + day
}  




pub fn days_to_be_age(age : usize) -> usize {

    let local: DateTime<Local> = Local::now();
    let today = local.date_naive();
    let year = today.year() as usize;
    let month = today.month() as usize;
    let mut day = today.day() as usize;

    let today_stamp = ymd_to_ordinal(year, month, day);
    if month == 2 && day == 29 {
        day = 28;
    }
    let past_stamp = ymd_to_ordinal(year - age, month, day);

    assert!(today_stamp > past_stamp);
    println!("To be {} years old, you must be {} days old", age, today_stamp - past_stamp);

    today_stamp - past_stamp
}