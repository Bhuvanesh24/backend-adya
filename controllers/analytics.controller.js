import Application from '../models/Application.js';
import User from '../models/User.js';


export const getApplicationStats = async (req, res) => {
  console.log("Callled");
  try {
    const userId = req.user.id;
    const { period = 'all' } = req.query; 

    const user = await User.findById(userId).populate('applications');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    let applications = user.applications;
    const currentDate = new Date();

    
    if (period !== 'all') {
      const startDate = new Date();
      switch (period) {
        case 'week':
          startDate.setDate(currentDate.getDate() - 7);
          break;
        case 'month':
          startDate.setMonth(currentDate.getMonth() - 1);
          break;
        case 'year':
          startDate.setFullYear(currentDate.getFullYear() - 1);
          break;
      }
      applications = applications.filter(app => 
        new Date(app.createdAt) >= startDate
      );
    }

    // Calculate statistics
    const totalApplications = applications.length;
    const statusCounts = {
      applied: 0,
      'under review': 0,
      'interview scheduled': 0,
      offered: 0,
      rejected: 0
    };

    const companyCounts = {};
    const monthlyStats = {};
    
    applications.forEach(app => {
      // Count by status
      statusCounts[app.currentStatus] = (statusCounts[app.currentStatus] || 0) + 1;
      
      // Count by company
      companyCounts[app.company] = (companyCounts[app.company] || 0) + 1;
      
      // Monthly statistics
      const month = new Date(app.createdAt).toISOString().slice(0, 7); // YYYY-MM
      monthlyStats[month] = (monthlyStats[month] || 0) + 1;
    });

    // Calculate success metrics
    const interviewRate = totalApplications > 0 
      ? ((statusCounts['interview scheduled'] + statusCounts.offered) / totalApplications * 100).toFixed(2)
      : 0;
    
    const offerRate = totalApplications > 0 
      ? (statusCounts.offered / totalApplications * 100).toFixed(2)
      : 0;

    // Top companies applied to
    const topCompanies = Object.entries(companyCounts)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10)
      .map(([company, count]) => ({ company, count }));

    // Monthly timeline
    const timeline = Object.entries(monthlyStats)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([month, count]) => ({ month, count }));

    const stats = {
      totalApplications,
      statusBreakdown: statusCounts,
      interviewRate: parseFloat(interviewRate),
      offerRate: parseFloat(offerRate),
      topCompanies,
      timeline,
      period
    };

    res.status(200).json({
      success: true,
      data: stats
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching application statistics',
      error: error.message
    });
  }
};

// Get application timeline for a specific application
export const getApplicationTimeline = async (req, res) => {
  try {
    const { applicationId } = req.params;
    const userId = req.user.id;

    
    const user = await User.findById(userId);
    if (!user.applications.includes(applicationId)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied to this application'
      });
    }

    const application = await Application.findById(applicationId);
    if (!application) {
      return res.status(404).json({
        success: false,
        message: 'Application not found'
      });
    }

    // Create timeline combining status history and communications
    const timeline = [];

    // Add status history to timeline
    application.statusHistory.forEach(status => {
      timeline.push({
        type: 'status_change',
        date: status.updatedAt,
        title: `Status changed to: ${status.status}`,
        description: status.note,
        updatedBy: status.updatedBy
      });
    });

    // Add communications to timeline
    application.communications.forEach(comm => {
      timeline.push({
        type: 'communication',
        date: comm.date,
        title: `Communication via ${comm.mode}`,
        description: comm.summary,
        contactPerson: comm.contactPerson
      });
    });

    // Add reminders to timeline
    application.reminders.forEach(reminder => {
      timeline.push({
        type: 'reminder',
        date: reminder.dueDate,
        title: `${reminder.type} reminder`,
        description: reminder.note,
        isCompleted: reminder.isCompleted,
        isPast: new Date(reminder.dueDate) < new Date()
      });
    });

    // Sort timeline by date
    timeline.sort((a, b) => new Date(a.date) - new Date(b.date));

    res.status(200).json({
      success: true,
      data: {
        application: {
          jobTitle: application.jobTitle,
          company: application.company,
          currentStatus: application.currentStatus
        },
        timeline
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching application timeline',
      error: error.message
    });
  }
};

// Get dashboard summary
export const getDashboardSummary = async (req, res) => {
  console.log("Called");

  try {
    const userId = req.user.id;

    const user = await User.findById(userId).populate('applications');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    const currentDate = new Date();
    const weekAgo = new Date();
    weekAgo.setDate(currentDate.getDate() - 7);

    const recentApplications = user.applications.filter(app =>
      new Date(app.createdAt) >= weekAgo
    );

    const activeApplications = user.applications.filter(app =>
      !['rejected', 'offered'].includes(app.currentStatus)
    );

    const upcomingReminders = [];
    const nextWeek = new Date();
    nextWeek.setDate(currentDate.getDate() + 7);

    user.applications.forEach(app => {
      if (Array.isArray(app.reminders)) {
        app.reminders.forEach(reminder => {
          const reminderDate = new Date(reminder.dueDate);
          if (
            !reminder.isCompleted &&
            reminderDate >= currentDate &&
            reminderDate <= nextWeek
          ) {
            upcomingReminders.push({
              ...reminder.toObject(),
              applicationId: app._id,
              jobTitle: app.jobTitle,
              company: app.company,
            });
          }
        });
      }
    });

    const overdueReminders = [];
    user.applications.forEach(app => {
      if (Array.isArray(app.reminders)) {
        app.reminders.forEach(reminder => {
          const reminderDate = new Date(reminder.dueDate);
          if (!reminder.isCompleted && reminderDate < currentDate) {
            overdueReminders.push({
              ...reminder.toObject(),
              applicationId: app._id,
              jobTitle: app.jobTitle,
              company: app.company,
            });
          }
        });
      }
    });

    const interviewsScheduled = user.applications.filter(
      app => app.currentStatus === 'interview scheduled'
    ).length;

    const weeklyGoal = user.jobGoals?.weeklyTarget || 0;
    const currentWeekCount = user.jobGoals?.currentWeekCount || 0;
    const goalProgress =
      weeklyGoal > 0 ? (currentWeekCount / weeklyGoal) * 100 : 0;

    const summary = {
      totalApplications: user.applications.length,
      activeApplications: activeApplications.length,
      recentApplications: recentApplications.length,
      interviewsScheduled,
      upcomingReminders: upcomingReminders.length,
      overdueReminders: overdueReminders.length,
      weeklyGoal: {
        target: weeklyGoal,
        current: currentWeekCount,
        progress: Math.round(goalProgress),
      },
      upcomingRemindersList: upcomingReminders.slice(0, 5),
      overdueRemindersList: overdueReminders.slice(0, 5),
    };

    res.status(200).json({
      success: true,
      data: summary,
    });
  } catch (error) {
    console.error("Dashboard error:", error);
    res.status(500).json({
      success: false,
      message: 'Error fetching dashboard summary',
      error: error.message,
    });
  }
};
