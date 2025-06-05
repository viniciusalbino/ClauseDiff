// Export all page objects for easy importing
export { BasePage } from './BasePage'
export { LoginPage } from './LoginPage'
export { RegisterPage } from './RegisterPage'
export { DocumentComparisonPage } from './DocumentComparisonPage'

// Import classes for creating instances
import { LoginPage } from './LoginPage'
import { RegisterPage } from './RegisterPage'
import { DocumentComparisonPage } from './DocumentComparisonPage'

// Create instances for immediate use
export const loginPage = new LoginPage()
export const registerPage = new RegisterPage()
export const documentComparisonPage = new DocumentComparisonPage() 